#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
npm ci --ignore-scripts --no-audit --no-fund
npm run build
node --test dist/tests/setup-fast-path.test.js
printf 'setup cancellation integration: no-mutation, rollback, final-readiness, and rollback-failure checkpoints passed\n'
