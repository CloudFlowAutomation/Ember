"""CommSecure lobby as a single Lambda function (no web framework).

POST /rooms                -> run a room MicroVM, register the join code in DynamoDB
POST /rooms/join           -> look the code up, return the MicroVM url + auth token
GET  /rooms/{code}         -> room state (client polls this while the VM starts)
POST /rooms/{code}/extend  -> push back the expiry (creator only, X-Host-Key)
DELETE /rooms/{code}       -> end the room now (creator only, X-Host-Key)

Same request/response shapes as app/lobby.py, so the Electron app only
needs LOBBY_URL pointed at this function's URL.

Handler: lobby_lambda.lambda_handler. boto3 is bundled into the zip by
main.tf — the runtime's copy is too old to know lambda-microvms. Env: ROOMS_TABLE (default commsecure-rooms), MICROVM_IMAGE_ARN
(required), MICROVM_EXECUTION_ROLE_ARN, ROOM_IDLE_SECONDS (default 600).
DynamoDB table: partition key `code` (S); enable TTL on `expires_at`.

Deploy: `terraform apply` in this folder provisions all of the above
(function + Function URL, table, IAM role) — see main.tf.
"""

import base64
import json
import math
import os
import secrets
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION") or "us-east-1"
IMAGE_ARN = os.environ.get("MICROVM_IMAGE_ARN", "")
EXECUTION_ROLE_ARN = os.environ.get("MICROVM_EXECUTION_ROLE_ARN", "")
ROOMS_TABLE = os.environ.get("ROOMS_TABLE", "commsecure-rooms")
ROOM_IDLE_SECONDS = int(os.environ.get("ROOM_IDLE_SECONDS", "600"))
ROOM_PORT = 8080
MIN_MINUTES = 5
MAX_MINUTES = 480

INGRESS_ARN = f"arn:aws:lambda:{REGION}:aws:network-connector:aws-network-connector:ALL_INGRESS"
EGRESS_ARN = f"arn:aws:lambda:{REGION}:aws:network-connector:aws-network-connector:INTERNET_EGRESS"

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

mvm = boto3.client("lambda-microvms", region_name=REGION)
rooms = boto3.resource("dynamodb", region_name=REGION).Table(ROOMS_TABLE)

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "*",
    "Access-Control-Allow-Headers": "*",
}


def reply(status, body=None):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", **CORS},
        "body": json.dumps(body if body is not None else {}),
    }


def error(status, detail):
    return reply(status, {"detail": detail})


def iso(ts):
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()


def normalize_code(code):
    return "".join(c for c in code.upper() if c in CODE_ALPHABET)


def get_room(code):
    """Return (item, error_response); the registry is the DynamoDB table."""
    item = rooms.get_item(Key={"code": normalize_code(code)}).get("Item")
    if item is None:
        return None, error(404, "Unknown join code")
    if int(item["expires_at"]) <= time.time():
        return None, error(410, "This room has expired")
    return item, None


def create_room(body):
    if not IMAGE_ARN:
        return error(503, "Lobby is not configured: set MICROVM_IMAGE_ARN")
    minutes = body.get("duration_minutes")
    if not isinstance(minutes, int) or not MIN_MINUTES <= minutes <= MAX_MINUTES:
        return error(422, f"duration_minutes must be {MIN_MINUTES}-{MAX_MINUTES}")
    name = str(body.get("name") or "Private room")[:64]
    allow_extend = bool(body.get("allow_extend", True))

    created_at = int(time.time())
    expires_at = created_at + minutes * 60
    control_key = secrets.token_urlsafe(24)
    kwargs = {
        "imageIdentifier": IMAGE_ARN,
        # The platform offers no way to lengthen a running VM's duration, so
        # extendable rooms set the hard stop to the 8 h platform cap purely
        # as a backstop and the *chosen* expiry is enforced by the relay's
        # watchdog — which is what makes /rooms/{code}/extend possible.
        # Non-extendable rooms keep the hard stop at the chosen duration.
        "maximumDurationInSeconds": (MAX_MINUTES if allow_extend else minutes) * 60,
        "ingressNetworkConnectors": [INGRESS_ARN],
        "egressNetworkConnectors": [EGRESS_ARN],
        "idlePolicy": {
            "autoResumeEnabled": True,
            "maxIdleDurationSeconds": ROOM_IDLE_SECONDS,
            "suspendedDurationSeconds": ROOM_IDLE_SECONDS,
        },
        "runHookPayload": json.dumps(
            {
                "name": name,
                "expiresAt": expires_at,
                "idleTimeoutSeconds": ROOM_IDLE_SECONDS,
                "region": REGION,
                # Authorizes lobby -> relay /room/extend calls; never
                # revealed to room members.
                "controlKey": control_key,
            }
        ),
    }
    if EXECUTION_ROLE_ARN:
        kwargs["executionRoleArn"] = EXECUTION_ROLE_ARN
    resp = mvm.run_microvm(**kwargs)

    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    # Returned once to the creator; lets them extend the room.
    host_key = secrets.token_urlsafe(24)
    rooms.put_item(
        Item={
            "code": code,
            "microvm_id": resp["microvmId"],
            "endpoint": resp["endpoint"],
            "name": name,
            "created_at": created_at,
            "expires_at": expires_at,  # TTL attribute
            "control_key": control_key,
            "host_key": host_key,
            "allow_extend": allow_extend,
        }
    )
    return reply(
        201,
        {
            "join_code": f"{code[:4]}-{code[4:]}",
            "host_key": host_key,
            "name": name,
            "microvm_id": resp["microvmId"],
            "state": resp.get("state", "PENDING"),
            "expires_at": iso(expires_at),
            "allow_extend": allow_extend,
        },
    )


def mint_token(microvm_id, minutes):
    resp = mvm.create_microvm_auth_token(
        microvmIdentifier=microvm_id,
        expirationInMinutes=minutes,
        allowedPorts=[{"port": ROOM_PORT}],
    )
    token = resp["authToken"]
    if isinstance(token, dict):
        token = token.get("X-aws-proxy-auth") or next(iter(token.values()))
    return token


def join_room(body):
    item, err = get_room(str(body.get("code", "")))
    if err:
        return err
    remaining = max(1, math.ceil((int(item["expires_at"]) - time.time()) / 60))
    token = mint_token(item["microvm_id"], remaining)
    state = mvm.get_microvm(microvmIdentifier=item["microvm_id"]).get("state")
    return reply(
        200,
        {
            "url": f"https://{item['endpoint']}",
            "token": token,
            "state": state,
            "name": item["name"],
            "expires_at": iso(item["expires_at"]),
            "allow_extend": bool(item.get("allow_extend", True)),
            "subprotocols": ["lambda-microvms", f"lambda-microvms.authentication.{token}"],
        },
    )


def extend_room(code, body, headers):
    """Push back a room's expiry — creator only (X-Host-Key). Capped at
    8 h total lifetime because that is the platform's hard stop."""
    item, err = get_room(code)
    if err:
        return err
    # Rooms registered before host keys existed can never be extended.
    if not item.get("host_key"):
        return error(403, "Invalid host key")
    if not secrets.compare_digest(str(headers.get("x-host-key") or ""), str(item["host_key"])):
        return error(403, "Invalid host key")
    if not item.get("allow_extend", True):
        return error(403, "This room was created with extensions disabled")
    minutes = body.get("additional_minutes")
    if not isinstance(minutes, int) or not 5 <= minutes <= MAX_MINUTES:
        return error(422, f"additional_minutes must be 5-{MAX_MINUTES}")

    hard_stop = int(item["created_at"]) + MAX_MINUTES * 60
    new_expires = int(item["expires_at"]) + minutes * 60
    if new_expires > hard_stop:
        spare = (hard_stop - int(item["expires_at"])) // 60
        return error(
            409,
            f"Rooms cannot live past {MAX_MINUTES // 60} h total; "
            + (f"this one can be extended by at most {spare} more minutes." if spare >= 1
               else "this room cannot be extended any further."),
        )

    # The relay's watchdog enforces the real expiry, so it must accept the
    # new deadline before the registry does. Reaching its endpoint needs a
    # platform token (which also auto-resumes a suspended room).
    token = mint_token(item["microvm_id"], 5)
    call = urllib.request.Request(
        f"https://{item['endpoint']}/room/extend",
        data=json.dumps(
            {"controlKey": str(item.get("control_key") or ""), "expiresAt": new_expires}
        ).encode(),
        headers={"Content-Type": "application/json", "X-aws-proxy-auth": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(call, timeout=30):
            pass
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # The room's VM snapshot predates /room/extend (image rebuilt
            # since, or never rebuilt). Only a new room picks up new code.
            return error(
                502,
                "This room is running an older build that cannot be extended; "
                "create a new room to get an extendable one.",
            )
        return error(502, f"Could not reach the room to extend it: {e}")
    except (urllib.error.URLError, TimeoutError) as e:
        return error(502, f"Could not reach the room to extend it: {e}")

    rooms.put_item(Item={**item, "expires_at": new_expires})
    return reply(200, {"name": item["name"], "expires_at": iso(new_expires)})


def close_room(code, headers):
    """End a room immediately — creator only (X-Host-Key)."""
    item, err = get_room(code)
    if err:
        return err
    if not item.get("host_key"):
        return error(403, "Invalid host key")
    if not secrets.compare_digest(str(headers.get("x-host-key") or ""), str(item["host_key"])):
        return error(403, "Invalid host key")

    # Best-effort heads-up via the relay so members see "the host ended the
    # room" instead of a bare disconnect; rooms on an older image 404 here.
    try:
        token = mint_token(item["microvm_id"], 5)
        call = urllib.request.Request(
            f"https://{item['endpoint']}/room/close",
            data=json.dumps({"controlKey": str(item.get("control_key") or "")}).encode(),
            headers={"Content-Type": "application/json", "X-aws-proxy-auth": token},
            method="POST",
        )
        with urllib.request.urlopen(call, timeout=15):
            pass
    except (ClientError, urllib.error.URLError, TimeoutError):
        pass
    # The notified relay terminates its own VM; this covers rooms that
    # could not be reached, and is a no-op if the VM is already going down.
    try:
        mvm.terminate_microvm(microvmIdentifier=item["microvm_id"])
    except ClientError:
        pass
    rooms.delete_item(Key={"code": normalize_code(code)})
    return reply(200, {})


def room_status(code):
    item, err = get_room(code)
    if err:
        return err
    state = mvm.get_microvm(microvmIdentifier=item["microvm_id"]).get("state")
    return reply(200, {"name": item["name"], "state": state, "expires_at": iso(item["expires_at"])})


def lambda_handler(event, context):
    http = event.get("requestContext", {}).get("http", {})
    method = http.get("method", "")
    path = event.get("rawPath", "")

    if method == "OPTIONS":  # CORS preflight from the app's file:// origin
        return {"statusCode": 204, "headers": CORS}

    body = {}
    if event.get("body"):
        raw = event["body"]
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw)
        try:
            body = json.loads(raw)
        except (ValueError, TypeError):
            return error(400, "Invalid JSON body")

    # Function URLs lowercase incoming header names; normalize anyway.
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    try:
        if method == "POST" and path == "/rooms":
            return create_room(body)
        if method == "POST" and path == "/rooms/join":
            return join_room(body)
        if method == "POST" and path.startswith("/rooms/") and path.endswith("/extend"):
            return extend_room(
                path.removeprefix("/rooms/").removesuffix("/extend"), body, headers
            )
        if method == "DELETE" and path.startswith("/rooms/"):
            return close_room(path.removeprefix("/rooms/"), headers)
        if method == "GET" and path.startswith("/rooms/"):
            return room_status(path.removeprefix("/rooms/"))
    except ClientError as e:
        err = e.response.get("Error", {})
        return error(502, f"AWS {err.get('Code', 'error')}: {err.get('Message', str(e))}")
    return error(404, "Not found")
