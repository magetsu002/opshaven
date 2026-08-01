#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
npm ci --ignore-scripts --no-audit --no-fund
npm run build
node --test dist/tests/setup-state.test.js dist/tests/remote-setup-trust.test.js
printf 'setup synchronization integration: canonical classification and signed-state reuse passed\n'
