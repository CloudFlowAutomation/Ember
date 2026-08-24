"""Ember room lobby — control plane for private rooms.

Creates one AWS Lambda MicroVM per private room from a pre-built relay
image (scripts/deploy_room_image.sh) and maps short join codes to the
room's dedicated HTTPS endpoint. Joining exchanges a code for the
endpoint URL plus a platform JWE auth token whose expiration equals the
room's remaining lifetime — the MicroVM endpoint itself rejects requests
without it, so the relay needs no auth code of its own.

Lifetime rules:
  - The creator picks the room duration; `maximumDurationInSeconds`
    hard-terminates the VM at that point no matter what.
  - No messages for ROOM_IDLE_SECONDS (default 10 min) and the relay
    terminates its own VM (see room_watchdog in app/main.py).
  - An *empty* room (no connections at all, hence no heartbeat traffic)
    is suspended by the platform idle policy after the same window and
    auto-resumes when someone with a valid token connects.

Run:  uv run uvicorn app.lobby:app --port 8100
Env:  MICROVM_IMAGE_ARN (required), AWS_REGION,
      MICROVM_EXECUTION_ROLE_ARN (lets rooms self-terminate),
      ROOM_IDLE_SECONDS (default 600).
"""

import asyncio
import json
import math
import os
import secrets
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
IMAGE_ARN = os.environ.get("MICROVM_IMAGE_ARN", "")
EXECUTION_ROLE_ARN = os.environ.get("MICROVM_EXECUTION_ROLE_ARN", "")
ROOM_IDLE_SECONDS = int(os.environ.get("ROOM_IDLE_SECONDS", "600"))
ROOM_PORT = 8080  # the MicroVM endpoint's default target port
MIN_MINUTES = 5
MAX_MINUTES = 480  # platform cap: maximum-duration-in-seconds tops out at 8 h

# Lambda-managed network connectors: public ingress for the room endpoint,
# internet egress so the room can call terminate-microvm on itself.
INGRESS_ARN = f"arn:aws:lambda:{REGION}:aws:network-connector:aws-network-connector:ALL_INGRESS"
EGRESS_ARN = f"arn:aws:lambda:{REGION}:aws:network-connector:aws-network-connector:INTERNET_EGRESS"

# Join-code alphabet omits lookalikes (I/L/O/0/1) — codes get read aloud.
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

# code -> {"microvm_id", "endpoint", "name", "expires_at", "host_key"}
rooms: dict[str, dict] = {}

_client = None


def mvm():
    global _client
    if _client is None:
        _client = boto3.client("lambda-microvms", region_name=REGION)
    return _client


def new_join_code() -> str:
    while True:
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
        if code not in rooms:
            return code


def normalize_code(code: str) -> str:
    return "".join(c for c in code.upper() if c in CODE_ALPHABET)


def pretty_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def aws_error(e: ClientError) -> HTTPException:
    err = e.response.get("Error", {})
    return HTTPException(
        status_code=502,
        detail=f"AWS {err.get('Code', 'error')}: {err.get('Message', str(e))}",
    )


async def reaper() -> None:
    """Drop expired registry entries; VM termination is belt-and-braces
    (the platform already enforces maximumDurationInSeconds)."""
    while True:
        await asyncio.sleep(60)
        now = time.time()
        for code in [c for c, r in rooms.items() if r["expires_at"] <= now]:
            info = rooms.pop(code)
            try:
                await asyncio.to_thread(
                    lambda: mvm().terminate_microvm(microvmIdentifier=info["microvm_id"])
                )
            except Exception:  # noqa: BLE001 — already gone is fine
                pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.get_running_loop().create_task(reaper())
    yield
    task.cancel()


app = FastAPI(title="Ember Room Lobby", lifespan=lifespan)

# The Electron renderer calls us from a file:// origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class CreateRoom(BaseModel):
    duration_minutes: int = Field(ge=MIN_MINUTES, le=MAX_MINUTES)
    name: str = Field(default="Private room", min_length=1, max_length=64)
    allow_extend: bool = True


class JoinRoom(BaseModel):
    code: str = Field(min_length=1, max_length=16)


class ExtendRoom(BaseModel):
    additional_minutes: int = Field(ge=5, le=MAX_MINUTES)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "rooms": len(rooms)}


@app.post("/rooms", status_code=201)
def create_room(req: CreateRoom) -> dict:
    """Launch a MicroVM for a new private room and mint its join code."""
    if not IMAGE_ARN:
        raise HTTPException(503, "Lobby is not configured: set MICROVM_IMAGE_ARN")

    created_at = time.time()
    expires_at = created_at + req.duration_minutes * 60
    control_key = secrets.token_urlsafe(24)
    kwargs = {
        "imageIdentifier": IMAGE_ARN,
        # The platform offers no way to lengthen a running VM's duration
        # (there is no UpdateMicrovm), so the hard stop is set to the 8 h
        # platform cap purely as a backstop and the *chosen* expiry is
        # enforced by the relay's watchdog plus our reaper — which is what
        # makes /rooms/{code}/extend possible.
        "maximumDurationInSeconds": MAX_MINUTES * 60,
        "ingressNetworkConnectors": [INGRESS_ARN],
        "egressNetworkConnectors": [EGRESS_ARN],
        # Suspends *empty* rooms (connected clients heartbeat, which counts
        # as traffic); silent-but-occupied rooms are ended by the relay's
        # own watchdog. suspendedDurationSeconds then reaps rooms nobody
        # ever returns to.
        "idlePolicy": {
            "autoResumeEnabled": True,
            "maxIdleDurationSeconds": ROOM_IDLE_SECONDS,
            "suspendedDurationSeconds": ROOM_IDLE_SECONDS,
        },
        "runHookPayload": json.dumps(
            {
                "name": req.name,
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

    try:
        resp = mvm().run_microvm(**kwargs)
    except ClientError as e:
        raise aws_error(e) from e

    code = new_join_code()
    rooms[code] = {
        "microvm_id": resp["microvmId"],
        "endpoint": resp["endpoint"],
        "name": req.name,
        "created_at": created_at,
        "expires_at": expires_at,
        "control_key": control_key,
        "allow_extend": req.allow_extend,
        # Returned once to the creator; lets them close or extend the room.
        "host_key": secrets.token_urlsafe(24),
    }
    return {
        "join_code": pretty_code(code),
        "host_key": rooms[code]["host_key"],
        "name": req.name,
        "microvm_id": resp["microvmId"],
        "state": resp.get("state", "PENDING"),
        "expires_at": iso(expires_at),
        "allow_extend": req.allow_extend,
    }


def _lookup(code: str) -> tuple[str, dict]:
    key = normalize_code(code)
    info = rooms.get(key)
    if info is None:
        raise HTTPException(404, "Unknown join code")
    if info["expires_at"] <= time.time():
        rooms.pop(key, None)
        raise HTTPException(410, "This room has expired")
    return key, info


@app.get("/rooms/{code}")
def room_status(code: str) -> dict:
    """Room state, e.g. for polling until RUNNING after creation."""
    _, info = _lookup(code)
    try:
        state = mvm().get_microvm(microvmIdentifier=info["microvm_id"]).get("state")
    except ClientError as e:
        raise aws_error(e) from e
    return {"name": info["name"], "state": state, "expires_at": iso(info["expires_at"])}


def _mint_token(microvm_id: str, minutes: int) -> str:
    resp = mvm().create_microvm_auth_token(
        microvmIdentifier=microvm_id,
        expirationInMinutes=minutes,
        allowedPorts=[{"port": ROOM_PORT}],
    )
    token = resp["authToken"]
    if isinstance(token, dict):  # docs show {"X-aws-proxy-auth": "<JWE>"}
        token = token.get("X-aws-proxy-auth") or next(iter(token.values()))
    return token


@app.post("/rooms/join")
def join_room(req: JoinRoom) -> dict:
    """Exchange a join code for the room's endpoint and an auth token
    that expires when the room does."""
    key, info = _lookup(req.code)
    remaining_minutes = max(1, math.ceil((info["expires_at"] - time.time()) / 60))
    try:
        token = _mint_token(info["microvm_id"], remaining_minutes)
        state = mvm().get_microvm(microvmIdentifier=info["microvm_id"]).get("state")
    except ClientError as e:
        raise aws_error(e) from e

    return {
        "url": f"https://{info['endpoint']}",
        "token": token,
        "state": state,
        "name": info["name"],
        "expires_at": iso(info["expires_at"]),
        "allow_extend": info.get("allow_extend", True),
        # Browser WebSocket clients can't set headers; the endpoint
        # accepts the token via these subprotocols instead.
        "subprotocols": ["lambda-microvms", f"lambda-microvms.authentication.{token}"],
    }


@app.post("/rooms/{code}/extend")
def extend_room(code: str, req: ExtendRoom, x_host_key: str = Header(default="")) -> dict:
    """Push back a room's expiry — creator only (X-Host-Key). Capped at
    8 h total lifetime because that is the platform's hard stop."""
    key, info = _lookup(code)
    if not secrets.compare_digest(x_host_key, info["host_key"]):
        raise HTTPException(403, "Invalid host key")
    if not info.get("allow_extend", True):
        raise HTTPException(403, "This room was created with extensions disabled")

    hard_stop = info["created_at"] + MAX_MINUTES * 60
    new_expires = info["expires_at"] + req.additional_minutes * 60
    if new_expires > hard_stop:
        spare = int((hard_stop - info["expires_at"]) // 60)
        raise HTTPException(
            409,
            f"Rooms cannot live past {MAX_MINUTES // 60} h total; "
            + (f"this one can be extended by at most {spare} more minutes." if spare >= 1
               else "this room cannot be extended any further."),
        )

    # The relay's watchdog enforces the real expiry, so it must accept the
    # new deadline before the registry does. Reaching its endpoint needs a
    # platform token (which also auto-resumes a suspended room).
    try:
        token = _mint_token(info["microvm_id"], 5)
    except ClientError as e:
        raise aws_error(e) from e
    call = urllib.request.Request(
        f"https://{info['endpoint']}/room/extend",
        data=json.dumps({"controlKey": info["control_key"], "expiresAt": new_expires}).encode(),
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
            raise HTTPException(
                502,
                "This room is running an older build that cannot be extended; "
                "create a new room to get an extendable one.",
            ) from e
        raise HTTPException(502, f"Could not reach the room to extend it: {e}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise HTTPException(502, f"Could not reach the room to extend it: {e}") from e

    info["expires_at"] = new_expires
    return {"name": info["name"], "expires_at": iso(new_expires)}


@app.delete("/rooms/{code}", status_code=204)
def close_room(code: str, x_host_key: str = Header(default="")) -> None:
    """Early shutdown by the room's creator."""
    key, info = _lookup(code)
    if not secrets.compare_digest(x_host_key, info["host_key"]):
        raise HTTPException(403, "Invalid host key")
    # Best-effort heads-up via the relay so members see "the host ended the
    # room" instead of a bare disconnect; rooms on an older image 404 here.
    try:
        token = _mint_token(info["microvm_id"], 5)
        call = urllib.request.Request(
            f"https://{info['endpoint']}/room/close",
            data=json.dumps({"controlKey": info["control_key"]}).encode(),
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
        mvm().terminate_microvm(microvmIdentifier=info["microvm_id"])
    except ClientError:
        pass
    rooms.pop(key, None)
