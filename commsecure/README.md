# CommSecure desktop app

Electron client for CommSecure. All cryptography runs in the renderer; see
the repo root `README.md` for the E2E/forward-secrecy design and the shared
relay. This file covers running the app and deploying the **temporary
private-room infrastructure** it connects to.

## Run the app

```bash
npm install
npm start
```

## Deploy temporary room infrastructure

Private rooms run **one isolated relay per room**, each in its own AWS
Lambda MicroVM that hard-stops when the room's duration elapses. The lobby
(`app/lobby.py` at the repo root) is the control plane the app talks to.

### 1. One-time AWS setup

You need AWS credentials configured (`aws configure`) in your target region
(default `us-east-1`), plus:

- **S3 bucket** to hold the room-image code artifact.
- **Build role** — assumed by Lambda while building the room image.
  Trust `lambda.amazonaws.com` (`sts:AssumeRole`, `sts:TagSession`);
  permissions: `s3:GetObject` on the bucket and CloudWatch Logs
  `CreateLogGroup` / `CreateLogStream` / `PutLogEvents`.
- **Execution role** — assumed by each room VM so it can terminate itself
  after 10 idle minutes. Same trust policy; allow `lambda:TerminateMicrovm`.
  (Optional: without it, rooms still hard-stop at their duration, but
  silent-yet-occupied rooms won't end early.)

### 2. Build (or update) the room image

From the repo root:

```bash
S3_BUCKET=my-bucket \
BUILD_ROLE_ARN=arn:aws:iam::<account>:role/MicrovmBuildRole \
  scripts/deploy_room_image.sh
```

The script zips the relay (`Dockerfile`, `app/`, `src/`), uploads it to S3,
creates or updates the `commsecure-room` MicroVM image, and waits for the
build (progress in CloudWatch log group `/aws/lambda/microvms/commsecure-room`).
On success it prints the `MICROVM_IMAGE_ARN` to export. Optional env:
`AWS_REGION` (default `us-east-1`), `IMAGE_NAME` (default `commsecure-room`).

Re-run the same command any time the relay code changes; rooms created
afterwards use the updated image.

### 3. Start the lobby

```bash
export MICROVM_IMAGE_ARN=arn:aws:lambda:…:microvm-image:commsecure-room
export MICROVM_EXECUTION_ROLE_ARN=arn:aws:iam::<account>:role/CommSecureRoomRole
uv run uvicorn app.lobby:app --port 8100
```

Optional env: `AWS_REGION`, `ROOM_IDLE_SECONDS` (default 600).

### 4. Create and join rooms

In the app's connect screen, switch to **Private room**, pick a duration
(5 min – 8 h), and share the join code. Rooms are created and joined via
the default lobby at `http://localhost:8100`; to use a lobby hosted
elsewhere, set **Rooms API URL** under ⚙ Settings on the connect screen
(persisted across sessions; leave blank to return to the default —
non-local URLs must be HTTPS because of the app's content-security
policy). Joining exchanges the code for the room's HTTPS
endpoint plus an auth token that expires with the room — the MicroVM
endpoint itself rejects connections without it, so the relay stays
zero-knowledge with no auth code of its own.

Room lifetime: the platform hard-terminates the VM at the chosen duration;
the in-room watchdog ends rooms with no messages for 10 minutes; rooms with
no connections at all are suspended by the platform and auto-resume when a
valid token holder connects. Creating a room also returns a one-time
`host_key` — `DELETE {lobby}/rooms/{code}` with header `X-Host-Key` closes
it early.
