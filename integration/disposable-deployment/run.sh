#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

cd "$ROOT"
npm ci --ignore-scripts --no-audit --no-fund
npm run build

node --test \
  dist/tests/deployment-plans.test.js \
  dist/tests/deployment.test.js

cp -a integration/fixtures/sample-api "$WORK/sample-api"
cd "$WORK/sample-api"
npm run build

PORT="$(node -e 'const net=require("node:net");const server=net.createServer();server.listen(0,"127.0.0.1",()=>{console.log(server.address().port);server.close();});')"
PORT="$PORT" node server.mjs >"$WORK/healthy.log" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 50); do
  if curl --silent --show-error --fail "http://127.0.0.1:${PORT}/health" >"$WORK/health.json"; then
    break
  fi
  sleep 0.1
done

grep -F '"healthy":true' "$WORK/health.json" >/dev/null
grep -F '"revision":"2222222222222222222222222222222222222222"' "$WORK/health.json" >/dev/null
curl --silent --show-error --fail "http://127.0.0.1:${PORT}/version" >"$WORK/version.json"
grep -F '"revision":"2222222222222222222222222222222222222222"' "$WORK/version.json" >/dev/null

kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

PORT="$(node -e 'const net=require("node:net");const server=net.createServer();server.listen(0,"127.0.0.1",()=>{console.log(server.address().port);server.close();});')"
SAMPLE_API_UNHEALTHY=1 PORT="$PORT" node server.mjs >"$WORK/unhealthy.log" 2>&1 &
SERVER_PID="$!"

STATUS=""
for _ in $(seq 1 50); do
  STATUS="$(curl --silent --output "$WORK/unhealthy.json" --write-out '%{http_code}' "http://127.0.0.1:${PORT}/health" || true)"
  if [[ "$STATUS" == "503" ]]; then
    break
  fi
  sleep 0.1
done

[[ "$STATUS" == "503" ]]
grep -F '"healthy":false' "$WORK/unhealthy.json" >/dev/null

echo "disposable deployment integration: passed"
