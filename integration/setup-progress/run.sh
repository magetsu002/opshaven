#!/usr/bin/env bash
set -euo pipefail

npm ci --ignore-scripts --no-audit --no-fund
npm run build
node --test dist/tests/setup-progress.test.js

echo "setup-progress: TTY repaint, heartbeat cadence, dynamic numbering, non-TTY lines, and JSON silence passed"
