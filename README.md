# Ember – Community Secure Chat

End-to-end encrypted group chat with **perfect forward secrecy (PFS)** and
**post-quantum hybrid key agreement** (X25519 + ML-KEM-768, in the style of
Signal's PQXDH).

Two parts:

- **Relay server** (`app/`) — a zero-knowledge FastAPI + Socket.IO relay. It
  maintains a roster of `{sid, public key, username}` and forwards opaque
  ciphertext between clients. It stores no messages and never sees plaintext
  or private keys.
- **Ember desktop app** (`ember/`) — an Electron client themed to
  match TownCenter. All cryptography runs in the client.

## How forward secrecy works

1. **Ephemeral session keys.** Every connection generates a fresh X25519
   keypair *and* a fresh ML-KEM-768 (FIPS 203) keypair in renderer memory.
   Nothing is written to disk; keys are zeroed on disconnect. Compromise of a
   device tomorrow reveals nothing about today's sessions.
2. **Hybrid pairwise agreement (quantum-resistant).** Each sender's chain
   root is `H(X25519-ECDH-secret ‖ ML-KEM-768-shared-secret)`: the sender
   encapsulates to the peer's ML-KEM key and the encapsulation rides along
   with each message (`kx`, constant per session), so no handshake round is
   added. An adversary recording traffic today who later breaks X25519 with
   a quantum computer still lacks the ML-KEM secret — and vice versa.
3. **Per-message hash ratchet.** Each message is encrypted
   (XSalsa20-Poly1305) with a one-time key derived from the current chain key
   (SHA-512 KDF); the chain then advances and old key material is overwritten.
   Compromising current chain state cannot decrypt previously sent messages,
   and replayed ciphertexts are rejected.
4. **Group messages** are fanned out: the sender encrypts an independent copy
   for every roster member on that pairwise ratchet. A **direct message** is
   the same operation with exactly one recipient — nobody else, the relay
   included, ever receives ciphertext for it.

## Identity and MITM protection

Each client also holds a **persistent Ed25519 identity key**, generated on
first run and stored encrypted with the OS keychain (Electron `safeStorage`)
under the app's user data. Both ephemeral session keys (X25519 and ML-KEM)
are signed together by the identity key (with a domain-separation context),
and clients verify the signature on every roster entry — a relay that
substitutes either session key cannot forge it, and such peers are excluded
from all encryption.

Identity keys only sign; they never encrypt. Compromising one later allows
impersonation, not decryption of past traffic, so forward secrecy is intact.
(As in Signal's PQXDH, the identity layer stays classical Ed25519 — breaking
it retroactively gains an attacker nothing.)

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

Beyond the shared relay, Ember can run **one isolated relay per
private room**, each in its own [Lambda MicroVM](https://docs.aws.amazon.com/lambda/latest/dg/lambda-microvms-guide.html)
(a Firecracker VM with a dedicated HTTPS endpoint). The **lobby**
(`app/lobby.py`) is the control plane:

- `POST /rooms {"duration_minutes": N, "name": "..."}` launches a MicroVM
  from the room image and returns a **join code** (plus a `host_key` that
  lets the creator close the room early with `DELETE /rooms/{code}` or
  extend it). The creator picks the duration (5 min – 8 h). The platform
  offers no way to lengthen a running VM's `maximum-duration-in-seconds`,
  so it is set to the 8 h platform cap as a backstop while the *chosen*
  expiry is enforced by the in-room watchdog and the lobby's reaper.
- `POST /rooms/{code}/extend {"additional_minutes": N}` with header
  `X-Host-Key` pushes the expiry back (never past 8 h total lifetime).
  The lobby authenticates the creator, tells the room's relay the new
  deadline (authorized by a `controlKey` shared via the run hook — room
  members can't extend on their own), and the relay broadcasts
  `room_extended` so every client's in-app countdown updates.
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

   export MICROVM_IMAGE_ARN=arn:aws:lambda:…:microvm-image:ember-room
   export MICROVM_EXECUTION_ROLE_ARN=arn:aws:iam::…:role/emberRoomRole
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
cd ember
npm install
npm start
```

Enter a username and the server URL, then chat. Open a second instance to
talk to yourself across sessions.

Images (PNG, JPEG, GIF, WebP) and arbitrary files (up to ~1.4 MB) can be
sent with the 📎 button — images also by pasting into the message box. Both
ride the same per-peer encrypted ratchet as text — wrapped in a JSON
envelope, images downscaled client-side if large — so the relay never sees
content. Received files are saved via an explicit download; they are never
rendered or executed in the app.

Click a peer in the sidebar to switch the composer to a **direct message**
(click again, press ✕, or lose the peer to switch back). DMs are encrypted
to that peer alone and marked 🔒 in both clients.

In a private room, the chat header shows a live countdown to the room's
expiry. The room's creator (the client that created the join code) also
gets an **+ Extend** button there — +15 min / +30 min / +1 h, capped at 8 h
total room lifetime.

## Verify the encryption

With the server running:

```bash
cd ember
node test/e2e-sim.js http://127.0.0.1:8000
```

This drives two real clients through the relay and asserts: mutual
decryption, no plaintext on the wire, advancing ratchet counters with
distinct ciphertexts, and replay rejection.
