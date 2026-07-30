#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

if [ -n "$(git status --porcelain)" ]; then
  echo "Certification requires a clean working tree" >&2
  exit 1
fi
candidate="$(git rev-parse HEAD)"
work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

git clone --quiet --no-local "$root" "$work/repository"
cd "$work/repository"
[ "$(git rev-parse HEAD)" = "$candidate" ] || {
  echo "Clean clone did not resolve to the candidate head" >&2
  exit 1
}

npm install --ignore-scripts
npm run check
npm run test:security
npm run security:scan
npm audit --audit-level=high
npm run smoke
npm pack --dry-run >/dev/null

if [ "${OPSHAVEN_SKIP_INTEGRATION:-0}" = "1" ]; then
  echo "Disposable restricted-SSH integration was explicitly skipped; this run is not release certification." >&2
  exit 3
fi
npm run test:integration
printf 'OpsHaven candidate %s passed clean-clone and disposable-SSH certification.\n' "$candidate"
