#!/usr/bin/env bash
# Build and push authrs image to a public Docker registry (e.g. Docker Hub).
#
# Usage:
#   ./scripts/docker-build-push.sh [IMAGE[:TAG]]
#
# Examples:
#   ./scripts/docker-build-push.sh myuser/authrs           # build & push as myuser/authrs:latest
#   ./scripts/docker-build-push.sh myuser/authrs:v0.1.0    # build & push with tag v0.1.0
#   DOCKER_IMAGE=myuser/authrs ./scripts/docker-build-push.sh
#
# Prerequisites:
#   - docker login   (to Docker Hub or your registry)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="${DOCKER_IMAGE:-${1:-}}"
if [[ -z "$IMAGE" ]]; then
  echo "Usage: $0 <IMAGE[:TAG]>"
  echo "   or: DOCKER_IMAGE=username/authrs $0"
  echo "Example: $0 myuser/authrs:latest"
  exit 1
fi

# If IMAGE has no tag, default to latest
if [[ "$IMAGE" != *:* ]]; then
  IMAGE="${IMAGE}:latest"
fi

echo "Building $IMAGE ..."
docker build -t "$IMAGE" "$REPO_ROOT"

echo "Pushing $IMAGE ..."
docker push "$IMAGE"

echo "Done. Image pushed: $IMAGE"
