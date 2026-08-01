#!/usr/bin/env bash
set -euo pipefail

npm ci --ignore-scripts --no-audit --no-fund
npm run build
node --test dist/tests/setup-receipt-identity.test.js

echo "setup-receipt-tampering: staging-path stability and digest, generation, dispatcher, policy, and chain tampering rejection passed"
