#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

cd "$ROOT"
npm ci --ignore-scripts --no-audit --no-fund
npm run build

cp -a integration/fixtures/sample-api "$WORK/repository"
cd "$WORK/repository"
git init -q -b main
git config user.name "OpsHaven Synthetic Fixture"
git config user.email "fixture@example.invalid"
git add .
git commit -q -m "OpsHaven sample: current"
CURRENT="$(git rev-parse HEAD)"

printf 'healthy revision\n' > REVISION.txt
git add REVISION.txt
git commit -q -m "OpsHaven sample: healthy"
HEALTHY="$(git rev-parse HEAD)"

[[ "$CURRENT" =~ ^[0-9a-f]{40}$ ]]
[[ "$HEALTHY" =~ ^[0-9a-f]{40}$ ]]
[[ "$CURRENT" != "$HEALTHY" ]]
git merge-base --is-ancestor "$CURRENT" "$HEALTHY"

cd "$ROOT"
OPSHAVEN_SAMPLE_CURRENT_REVISION="$CURRENT" \
OPSHAVEN_SAMPLE_HEALTHY_REVISION="$HEALTHY" \
node --test dist/tests/deployment-onboarding.test.js

printf 'deployment onboarding integration: current=%s healthy=%s passed\n' "$CURRENT" "$HEALTHY"
