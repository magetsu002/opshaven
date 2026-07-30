#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="$ROOT/integration/disposable-vps"
GEN="$DIR/generated"
rm -rf "$GEN"
mkdir -p "$GEN"
ssh-keygen -q -t ed25519 -N '' -f "$GEN/id_ed25519"
cp "$GEN/id_ed25519.pub" "$GEN/authorized_key.pub"
cleanup() { docker compose -f "$DIR/compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$GEN"; }
trap cleanup EXIT
docker compose -f "$DIR/compose.yml" up -d --build

for _ in $(seq 1 40); do
  if ssh-keyscan -p 22222 127.0.0.1 > "$GEN/known_hosts" 2>/dev/null; then break; fi
  sleep 1
done
[[ -s "$GEN/known_hosts" ]]
SSH=(ssh -p 22222 -i "$GEN/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$GEN/known_hosts" -o ClearAllForwardings=yes -o ForwardAgent=no -o RequestTTY=no opshaven@127.0.0.1)

SHELL_RESULT="$(${SSH[@]} id 2>/dev/null || true)"
[[ "$SHELL_RESULT" == *'POLICY_DENIED'* ]]
[[ "$SHELL_RESULT" != *'uid='* ]]

REQUEST='{"version":1,"requestId":"integration-1","operation":"get_host_summary","resourceId":"host.fixture","args":{"resourceId":"host.fixture"},"limits":{"timeoutMs":10000,"maxBytes":65536,"maxLines":500}}'
RESPONSE="$(printf '%s\n' "$REQUEST" | "${SSH[@]}")"
node -e 'const x=JSON.parse(process.argv[1]); if(!x.ok || x.requestId!=="integration-1" || !x.data.uname) process.exit(1)' "$RESPONSE"
printf 'disposable-vps: restricted SSH and valid dispatcher request passed\n'
