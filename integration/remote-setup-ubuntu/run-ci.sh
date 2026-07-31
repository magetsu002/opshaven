#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="$(mktemp)"
cleanup() { rm -f "$LOG"; }
trap cleanup EXIT
set +e
OPSHAVEN_DEBUG=1 bash "$ROOT/integration/remote-setup-ubuntu/run.sh" >"$LOG" 2>&1
STATUS=$?
set -e
if [[ $STATUS -ne 0 ]]; then
  printf '%s\n' 'remote-setup-ubuntu failed; final diagnostic output:' >&2
  tail -n 80 "$LOG" >&2
  exit "$STATUS"
fi
cat "$LOG"
