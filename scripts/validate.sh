#!/bin/sh
set -eu

npm run check
npm run test:security
npm run security:scan
if [ "${OPSHAVEN_RUN_INTEGRATION:-0}" = "1" ]; then
  npm run test:integration
fi
