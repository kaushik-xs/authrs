#!/usr/bin/env bash
# Build and push authrs image to a public Docker registry (e.g. Docker Hub).
# Builds multi-platform image (linux/amd64, linux/arm64) so it runs on both
# x86_64 servers (e.g. Ubuntu on AWS) and ARM (e.g. Apple Silicon).
#
# The image is tagged with the semantic version from Cargo.toml, prefixed
# with "v" (e.g. v0.1.0). The repository is taken from the argument or
# DOCKER_IMAGE; any tag you pass is ignored. The release is refused if that
# version tag already exists in the registry (bump the Cargo.toml version
# to publish a new release).
#
# Usage:
#   ./scripts/docker-build-push.sh <IMAGE>
#
# Examples:
#   ./scripts/docker-build-push.sh myuser/authrs        # build & push myuser/authrs:v<Cargo version>
#   DOCKER_IMAGE=myuser/authrs ./scripts/docker-build-push.sh
#
# Prerequisites:
#   - docker login   (to Docker Hub or your registry)
#   - docker buildx  (create builder once: docker buildx create --use)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="${DOCKER_IMAGE:-${1:-}}"
if [[ -z "$IMAGE" ]]; then
  echo "Usage: $0 <IMAGE>"
  echo "   or: DOCKER_IMAGE=username/authrs $0"
  echo "Example: $0 myuser/authrs"
  exit 1
fi

# Strip any tag the caller passed; the tag is derived from Cargo.toml.
REPO="${IMAGE%%:*}"

# Read the package version from Cargo.toml (first version under [package]).
VERSION="$(awk -F'"' '/^\[package\]/{p=1} p&&/^version[[:space:]]*=/{print $2; exit}' "$REPO_ROOT/Cargo.toml")"
if [[ -z "$VERSION" ]]; then
  echo "Error: could not read version from $REPO_ROOT/Cargo.toml" >&2
  exit 1
fi

TAG="v${VERSION}"
TARGET="${REPO}:${TAG}"

# Refuse to overwrite an already-published version tag (option B).
if docker manifest inspect "$TARGET" >/dev/null 2>&1; then
  echo "Error: $TARGET already exists in the registry." >&2
  echo "Bump the version in Cargo.toml to publish a new release." >&2
  exit 1
fi

# Multi-platform so image works on linux/amd64 (e.g. Ubuntu) and linux/arm64 (e.g. Mac M1/M2)
PLATFORMS="${DOCKER_PLATFORMS:-linux/amd64,linux/arm64}"

echo "Building $TARGET for $PLATFORMS ..."
docker buildx build \
  --platform "$PLATFORMS" \
  --tag "$TARGET" \
  --push \
  "$REPO_ROOT"

echo "Done. Image pushed: $TARGET (platforms: $PLATFORMS)"
