#!/usr/bin/env bash
# Build (or update) the CommSecure room MicroVM image.
#
# Packages the relay + Dockerfile into a zip, uploads it to S3, and asks
# Lambda MicroVMs to build a snapshot image from it. The lobby then runs
# one MicroVM per private room from this image (MICROVM_IMAGE_ARN).
#
# Required env:
#   S3_BUCKET       bucket for the code artifact
#   BUILD_ROLE_ARN  IAM role Lambda assumes during the build
#                   (trust: lambda.amazonaws.com; perms: s3:GetObject on
#                   the bucket, CloudWatch Logs write — see README)
# Optional env:
#   AWS_REGION      default: us-east-1
#   IMAGE_NAME      default: commsecure-room
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
IMAGE_NAME="${IMAGE_NAME:-commsecure-room}"
: "${S3_BUCKET:?set S3_BUCKET}"
: "${BUILD_ROLE_ARN:?set BUILD_ROLE_ARN}"

BASE_IMAGE_ARN="arn:aws:lambda:${REGION}:aws:microvm-image:al2023-1"
ARTIFACT="s3://${S3_BUCKET}/commsecure/room-image.zip"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$REPO_ROOT"
rm -f room-image.zip
zip -r room-image.zip Dockerfile pyproject.toml uv.lock README.md app src \
  -x '*__pycache__*' -x '*.pyc'
aws s3 cp room-image.zip "$ARTIFACT" --region "$REGION"
rm -f room-image.zip

# The /run hook is what delivers per-room config (expiry, idle timeout),
# so hooks must be registered — which requires declaring the hook port.
# Each hook field is an ENABLED/DISABLED toggle; the service invokes the
# fixed /aws/lambda-microvms/runtime/v1/<hook> routes on this port.
HOOKS='{
  "port": 8080,
  "microvmImageHooks": {
    "ready": "ENABLED", "readyTimeoutInSeconds": 600,
    "validate": "ENABLED", "validateTimeoutInSeconds": 300
  },
  "microvmHooks": {
    "run": "ENABLED", "runTimeoutInSeconds": 30,
    "resume": "ENABLED", "resumeTimeoutInSeconds": 30,
    "suspend": "ENABLED", "suspendTimeoutInSeconds": 30,
    "terminate": "ENABLED", "terminateTimeoutInSeconds": 30
  }
}'

# get/update take --image-identifier as an ARN or ID, never the name, so
# resolve the name first (name-filter is a contains match — pin it exactly).
IMAGE_ARN="$(aws lambda-microvms list-microvm-images \
  --name-filter "$IMAGE_NAME" --region "$REGION" \
  --query "items[?name=='${IMAGE_NAME}'] | [0].imageArn" --output text)"

if [ -n "$IMAGE_ARN" ] && [ "$IMAGE_ARN" != "None" ]; then
  echo "Updating existing image ${IMAGE_NAME}..."
  aws lambda-microvms update-microvm-image \
    --image-identifier "$IMAGE_ARN" \
    --code-artifact "uri=${ARTIFACT}" \
    --base-image-arn "$BASE_IMAGE_ARN" \
    --build-role-arn "$BUILD_ROLE_ARN" \
    --hooks "$HOOKS" \
    --region "$REGION" \
    --description "CommSecure per-room relay $(date -u +%Y-%m-%dT%H:%M:%SZ)"
else
  echo "Creating image ${IMAGE_NAME}..."
  IMAGE_ARN="$(aws lambda-microvms create-microvm-image \
    --name "$IMAGE_NAME" \
    --code-artifact "uri=${ARTIFACT}" \
    --base-image-arn "$BASE_IMAGE_ARN" \
    --build-role-arn "$BUILD_ROLE_ARN" \
    --hooks "$HOOKS" \
    --region "$REGION" \
    --query imageArn --output text)"
fi

echo "Waiting for build (CloudWatch logs: /aws/lambda/microvms/${IMAGE_NAME})..."
while true; do
  STATE="$(aws lambda-microvms get-microvm-image \
    --image-identifier "$IMAGE_ARN" --region "$REGION" \
    --query state --output text)"
  echo "  state: ${STATE}"
  case "$STATE" in
    CREATED|UPDATED)
      echo "Done. Export this for the lobby:"
      echo "  export MICROVM_IMAGE_ARN=${IMAGE_ARN}"
      exit 0
      ;;
    *FAILED*)
      echo "Build failed — check the CloudWatch log group above." >&2
      exit 1
      ;;
  esac
  sleep 15
done
