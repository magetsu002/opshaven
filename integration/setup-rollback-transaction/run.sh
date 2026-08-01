#!/usr/bin/env bash
set -euo pipefail

npm ci --ignore-scripts --no-audit --no-fund
npm run build
node --test \
  dist/tests/setup-transaction-regression.test.js \
  dist/tests/setup-transaction-lifecycle.test.js

echo "setup-rollback-transaction: staged failure, verified rollback, blocked rollback failure, and runtime reuse passed"
