#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="localhost/opshaven-remote-mcp-test:${GITHUB_SHA:-local}"

if ! command -v podman >/dev/null 2>&1; then
  printf 'rootless Podman is required for remote MCP integration\n' >&2
  exit 1
fi
if [[ "$(id -u)" -eq 0 ]]; then
  printf 'remote MCP Podman integration must run as a non-root user\n' >&2
  exit 1
fi

cleanup() {
  podman image rm --force "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

podman build \
  --format docker \
  --pull=never \
  --file "$ROOT/integration/remote-mcp-podman/Containerfile" \
  --tag "$IMAGE" \
  "$ROOT"

podman run \
  --rm \
  --network slirp4netns:allow_host_loopback=false \
  --security-opt no-new-privileges \
  --cap-drop all \
  --pids-limit 128 \
  --memory 512m \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
  "$IMAGE"
