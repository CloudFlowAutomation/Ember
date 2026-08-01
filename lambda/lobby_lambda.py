"""CommSecure lobby as a single Lambda function (no web framework).

POST /rooms        -> run a room MicroVM, register the join code in DynamoDB
POST /rooms/join   -> look the code up, return the MicroVM url + auth token
GET  /rooms/{code} -> room state (client polls this while the VM starts)

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

    expires_at = int(time.time()) + minutes * 60
    kwargs = {
        "imageIdentifier": IMAGE_ARN,
        "maximumDurationInSeconds": minutes * 60,
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
            }
        ),
    }
    if EXECUTION_ROLE_ARN:
        kwargs["executionRoleArn"] = EXECUTION_ROLE_ARN
    resp = mvm.run_microvm(**kwargs)

    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    rooms.put_item(
        Item={
            "code": code,
            "microvm_id": resp["microvmId"],
            "endpoint": resp["endpoint"],
            "name": name,
            "expires_at": expires_at,  # TTL attribute
        }
    )
    return reply(
        201,
        {
            "join_code": f"{code[:4]}-{code[4:]}",
            "name": name,
            "microvm_id": resp["microvmId"],
            "state": resp.get("state", "PENDING"),
            "expires_at": iso(expires_at),
        },
    )


def join_room(body):
    item, err = get_room(str(body.get("code", "")))
    if err:
        return err
    remaining = max(1, math.ceil((int(item["expires_at"]) - time.time()) / 60))
    resp = mvm.create_microvm_auth_token(
        microvmIdentifier=item["microvm_id"],
        expirationInMinutes=remaining,
        allowedPorts=[{"port": ROOM_PORT}],
    )
    state = mvm.get_microvm(microvmIdentifier=item["microvm_id"]).get("state")
    token = resp["authToken"]
    if isinstance(token, dict):
        token = token.get("X-aws-proxy-auth") or next(iter(token.values()))
    return reply(
        200,
        {
            "url": f"https://{item['endpoint']}",
            "token": token,
            "state": state,
            "name": item["name"],
            "expires_at": iso(item["expires_at"]),
            "subprotocols": ["lambda-microvms", f"lambda-microvms.authentication.{token}"],
        },
    )


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

    try:
        if method == "POST" and path == "/rooms":
            return create_room(body)
        if method == "POST" and path == "/rooms/join":
            return join_room(body)
        if method == "GET" and path.startswith("/rooms/"):
            return room_status(path.removeprefix("/rooms/"))
    except ClientError as e:
        err = e.response.get("Error", {})
        return error(502, f"AWS {err.get('Code', 'error')}: {err.get('Message', str(e))}")
    return error(404, "Not found")
