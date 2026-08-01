"""CommSecure relay server.

A zero-knowledge Socket.IO relay: clients register an ephemeral X25519
public key, the server maintains a roster and forwards ciphertext between
peers. The server never sees plaintext or private keys, so it cannot
decrypt traffic — forward secrecy is enforced client-side via ephemeral
keys and a per-message hash ratchet.

The same app also runs as a private room on AWS Lambda MicroVMs: one
MicroVM per room, configured through the `/run` lifecycle hook by the
lobby (see app/lobby.py). In room mode the relay tracks message activity
and terminates its own MicroVM after ROOM_IDLE (10 min) without messages,
or when the room's expiration passes. Endpoint access control (the JWE
join token) is enforced by the MicroVM endpoint itself, upstream of us.
"""

import asyncio
import json
import time

import socketio
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

# The buffer must hold one encrypted image copy per recipient in a single
# packet (~2 MB each after base64 + envelope overhead), so allow ~16 peers.
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins="*",
    max_http_buffer_size=32_000_000,
)

fastapi_app = FastAPI(title="CommSecure Relay")

# Socket.IO handles /socket.io/*; everything else falls through to FastAPI
app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app)

# sid -> {"pubkey": str, "idpk": str, "sig": str, "username": str}
# pubkey: ephemeral X25519 session key; idpk: persistent Ed25519 identity
# key; sig: identity signature over the session key. All are opaque to the
# server — clients verify signatures themselves, so the relay stays
# untrusted for authenticity as well as confidentiality.
peers: dict[str, dict[str, str]] = {}

# ---- Private-room mode (AWS Lambda MicroVMs) ----
#
# Populated by the /run lifecycle hook when this process is a per-room
# MicroVM; None when running as a plain shared relay. Wall-clock (epoch)
# times are used throughout because a MicroVM can be suspended and
# resumed — monotonic clocks don't survive that boundary meaningfully.
room: dict | None = None  # {"microvm_id", "name", "expires_at", "idle_timeout", "region"}
last_activity: float = time.time()
_watchdog: asyncio.Task | None = None

HOOK_PREFIX = "/aws/lambda-microvms/runtime/v1"


def touch_activity() -> None:
    global last_activity
    last_activity = time.time()


def _terminate_self_blocking() -> None:
    """Terminate this MicroVM via the execution role's credentials."""
    import boto3  # deferred: not needed (or configured) as a plain relay

    boto3.client("lambda-microvms", region_name=room.get("region")).terminate_microvm(
        microvmIdentifier=room["microvm_id"]
    )


async def close_room(reason: str) -> None:
    """Tell clients why the room is ending, then terminate the MicroVM."""
    print(f"closing room: {reason}")
    await sio.emit("room_closed", {"reason": reason})
    for sid in list(peers):
        await sio.disconnect(sid)
    try:
        await asyncio.to_thread(_terminate_self_blocking)
    except Exception as e:  # noqa: BLE001 — termination is best-effort;
        # maximumDurationInSeconds still hard-stops the VM at expiry.
        print(f"self-terminate failed: {e}")


async def room_watchdog() -> None:
    """Terminate the room when it expires or goes idle.

    The platform idle policy only sees endpoint traffic, and Socket.IO
    heartbeats count as traffic — so a room full of silent clients would
    never suspend. This watchdog implements the real rule: no messages
    for `idle_timeout` seconds ends the room.
    """
    while room is not None:
        await asyncio.sleep(30)
        now = time.time()
        if now >= room["expires_at"]:
            await close_room("expired")
            return
        if now - last_activity >= room["idle_timeout"]:
            await close_room("idle")
            return

INFO_PAGE = """<!DOCTYPE html>
<html>
<head><title>CommSecure Relay</title></head>
<body style="font-family: Inter, system-ui, sans-serif; background: #f8fafc; color: #0f172a; padding: 48px;">
  <h1 style="letter-spacing: -0.02em;">CommSecure Relay</h1>
  <p style="color: #64748b; max-width: 60ch;">This server relays end-to-end
  encrypted messages for the CommSecure desktop app. It stores no messages
  and holds no keys.</p>
</body>
</html>"""


@fastapi_app.get("/")
async def index() -> HTMLResponse:
    return HTMLResponse(INFO_PAGE)


@fastapi_app.get("/health")
async def health() -> dict:
    info: dict = {"status": "ok"}
    if room is not None:
        info["room"] = {
            "name": room["name"],
            "expires_at": room["expires_at"],
            "idle_seconds": round(time.time() - last_activity),
        }
    return info


# ---- Lambda MicroVMs lifecycle hooks ----
#
# Lambda POSTs these during the image build (/ready, /validate) and the
# MicroVM lifecycle (/run, /resume, /suspend, /terminate). The endpoint
# gates external traffic until /run returns 200. Harmless when running
# as a plain relay — nothing calls them.


@fastapi_app.post(HOOK_PREFIX + "/ready")
@fastapi_app.post(HOOK_PREFIX + "/validate")
async def hook_ready() -> dict[str, str]:
    return {"status": "ok"}


@fastapi_app.post(HOOK_PREFIX + "/run")
async def hook_run(request: Request) -> dict[str, str]:
    """Adopt per-room config sent by the lobby via runHookPayload."""
    global room, _watchdog
    if _watchdog is not None:
        _watchdog.cancel()
    body = await request.json()
    config = json.loads(body.get("runHookPayload") or "{}")
    room = {
        "microvm_id": body.get("microvmId", ""),
        "name": str(config.get("name", "Private room"))[:64],
        "expires_at": float(config.get("expiresAt", time.time() + 3600)),
        "idle_timeout": int(config.get("idleTimeoutSeconds", 600)),
        "region": config.get("region"),
    }
    touch_activity()
    _watchdog = asyncio.get_running_loop().create_task(room_watchdog())
    print(f"room started: {room}")
    return {"status": "ok"}


@fastapi_app.post(HOOK_PREFIX + "/resume")
async def hook_resume() -> dict[str, str]:
    # Time suspended must not count as message idle, or a resumed room
    # would be reaped by the watchdog before anyone can speak.
    touch_activity()
    return {"status": "ok"}


@fastapi_app.post(HOOK_PREFIX + "/suspend")
@fastapi_app.post(HOOK_PREFIX + "/terminate")
async def hook_quiesce() -> dict[str, str]:
    return {"status": "ok"}


async def broadcast_roster() -> None:
    roster = [
        {
            "sid": sid,
            "pubkey": info["pubkey"],
            "idpk": info["idpk"],
            "sig": info["sig"],
            "username": info["username"],
        }
        for sid, info in peers.items()
    ]
    await sio.emit("roster", roster)


@sio.event
async def connect(sid: str, environ: dict) -> None:
    print(f"client connected: {sid}")


@sio.event
async def register(sid: str, data: dict) -> None:
    """Client announces its signed ephemeral session key and username."""
    pubkey = data.get("pubkey")
    idpk = data.get("idpk")
    sig = data.get("sig")
    username = data.get("username") or sid[:8]
    for field in (pubkey, idpk, sig):
        if not isinstance(field, str) or not field or len(field) > 256:
            return
    peers[sid] = {
        "pubkey": pubkey,
        "idpk": idpk,
        "sig": sig,
        "username": str(username)[:32],
    }
    touch_activity()
    await broadcast_roster()


@sio.event
async def e2e_message(sid: str, data: dict) -> None:
    """Fan out ciphertext to its recipients. Payloads are opaque to the server."""
    if sid not in peers:
        return
    recipients = data.get("recipients")
    if not isinstance(recipients, list):
        return
    touch_activity()
    for item in recipients:
        if not isinstance(item, dict):
            continue
        to = item.get("to")
        if to not in peers or to == sid:
            continue
        await sio.emit(
            "e2e_message",
            {
                "from": sid,
                "n": item.get("n"),
                "nonce": item.get("nonce"),
                "ct": item.get("ct"),
            },
            to=to,
        )


@sio.event
async def disconnect(sid: str) -> None:
    print(f"client disconnected: {sid}")
    if peers.pop(sid, None) is not None:
        await broadcast_roster()
