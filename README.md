# CommSecure – Community Secure Chat

End-to-end encrypted group chat with **perfect forward secrecy (PFS)**.

Two parts:

- **Relay server** (`app/`) — a zero-knowledge FastAPI + Socket.IO relay. It
  maintains a roster of `{sid, public key, username}` and forwards opaque
  ciphertext between clients. It stores no messages and never sees plaintext
  or private keys.
- **CommSecure desktop app** (`commsecure/`) — an Electron client themed to
  match TownCenter. All cryptography runs in the client.

## How forward secrecy works

1. **Ephemeral session keys.** Every connection generates a fresh X25519
   keypair in renderer memory. Nothing is written to disk; keys are zeroed on
   disconnect. Compromise of a device tomorrow reveals nothing about today's
   sessions.
2. **Pairwise ECDH.** Each pair of clients derives a shared root secret via
   `nacl.box.before` (X25519). Lexicographic public-key order symmetrically
   assigns each side its send/receive chain.
3. **Per-message hash ratchet.** Each message is encrypted
   (XSalsa20-Poly1305) with a one-time key derived from the current chain key
   (SHA-512 KDF); the chain then advances and old key material is overwritten.
   Compromising current chain state cannot decrypt previously sent messages,
   and replayed ciphertexts are rejected.
4. **Group messages** are fanned out: the sender encrypts an independent copy
   for every roster member on that pairwise ratchet.

## Identity and MITM protection

Each client also holds a **persistent Ed25519 identity key**, generated on
first run and stored encrypted with the OS keychain (Electron `safeStorage`)
under the app's user data. Every ephemeral session key is signed by the
identity key (with a domain-separation context), and clients verify the
signature on every roster entry — a relay that substitutes session keys
cannot forge them, and such peers are excluded from all encryption.

Identity keys only sign; they never encrypt. Compromising one later allows
impersonation, not decryption of past traffic, so forward secrecy is intact.

Identities are pinned **trust-on-first-use** per username: the first key seen
for a username is remembered, and a later mismatch raises a loud in-app
warning. The sidebar shows each peer's stable identity **fingerprint** —
compare it out-of-band (in person, another channel) to upgrade TOFU to real
verification. The relay remains trusted only for availability and metadata
(usernames, who talks when).

## Run the server

```bash
uv run uvicorn app.main:app --port 8000 --ws-max-size 32000000
# or
docker build -t sock . && docker run -p 8000:8080 sock
```

(`--ws-max-size` raises uvicorn's 16 MB websocket frame cap so encrypted
image messages — one ciphertext copy per recipient in a single packet —
fit; the Socket.IO server buffer is raised to match in `app/main.py`.)

## Private rooms on AWS Lambda MicroVMs

Beyond the shared relay, CommSecure can run **one isolated relay per
private room**, each in its own [Lambda MicroVM](https://docs.aws.amazon.com/lambda/latest/dg/lambda-microvms-guide.html)
(a Firecracker VM with a dedicated HTTPS endpoint). The **lobby**
(`app/lobby.py`) is the control plane:

- `POST /rooms {"duration_minutes": N, "name": "..."}` launches a MicroVM
  from the room image and returns a **join code** (plus a `host_key` for
  closing the room early with `DELETE /rooms/{code}`). The creator picks
  the duration (5 min – 8 h); `maximum-duration-in-seconds` hard-stops
  the VM when it elapses.
- `POST /rooms/join {"code": "XXXX-XXXX"}` resolves the code to that
  room's endpoint URL and mints a platform JWE auth token whose
  **expiration equals the room's remaining lifetime**. The MicroVM
  endpoint itself rejects requests without a valid token (WebSockets
  carry it via `lambda-microvms.*` subprotocols), so the relay contains
  no auth code and the zero-knowledge design is unchanged.
- **Idle timeout:** the relay tracks message activity and terminates its
  own MicroVM after 10 minutes without messages (`ROOM_IDLE_SECONDS`).
  Rooms with *no connections at all* are suspended by the platform idle
  policy instead (heartbeats from connected clients count as endpoint
  traffic, which is why the in-VM watchdog exists) and auto-resume when
  a holder of a valid token connects.

### One-time AWS setup

1. An S3 bucket for the code artifact.
2. A **build role** Lambda assumes while building the image — trust
   `lambda.amazonaws.com` (actions `sts:AssumeRole`, `sts:TagSession`);
   permissions: `s3:GetObject` on the bucket plus CloudWatch Logs
   `CreateLogGroup`/`CreateLogStream`/`PutLogEvents`.
3. An **execution role** for the room VMs (same trust policy) allowing
   `TerminateMicrovm`, so a room can end itself when idle. Check the
   exact action name with `aws iam list-policies`/docs — e.g.:

   ```json
   {"Effect": "Allow", "Action": "lambda:TerminateMicrovm", "Resource": "*"}
   ```

4. Build the room image and start the lobby:

   ```bash
   S3_BUCKET=my-bucket BUILD_ROLE_ARN=arn:aws:iam::…:role/MicrovmBuildRole \
     scripts/deploy_room_image.sh

   export MICROVM_IMAGE_ARN=arn:aws:lambda:…:microvm-image:commsecure-room
   export MICROVM_EXECUTION_ROLE_ARN=arn:aws:iam::…:role/CommSecureRoomRole
   uv run uvicorn app.lobby:app --port 8100
   ```

In the desktop app, pick **Private room**, create a room with a duration,
and share the join code. Or from the CLI:

```bash
curl -s localhost:8100/rooms -H 'content-type: application/json' \
  -d '{"duration_minutes": 60, "name": "ops sync"}'
curl -s localhost:8100/rooms/join -H 'content-type: application/json' \
  -d '{"code": "ABCD-EFGH"}'
```

## Run the desktop app

```bash
cd commsecure
npm install
npm start
```

Enter a username and the server URL, then chat. Open a second instance to
talk to yourself across sessions.

Images (PNG, JPEG, GIF, WebP) can be sent with the 📷 button or by pasting
into the message box. They ride the same per-peer encrypted ratchet as text
— wrapped in a JSON envelope, downscaled client-side if large — so the
relay never sees pixels.

## Verify the encryption

With the server running:

```bash
cd commsecure
node test/e2e-sim.js http://127.0.0.1:8000
```

This drives two real clients through the relay and asserts: mutual
decryption, no plaintext on the wire, advancing ratchet counters with
distinct ciphertexts, and replay rejection.
