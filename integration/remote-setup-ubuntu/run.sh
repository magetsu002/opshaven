#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="$ROOT/integration/remote-setup-ubuntu"
GEN="$DIR/generated"
STATE="$GEN/operator-state"
IMAGE="opshaven-remote-setup-ubuntu"
CONTAINER="opshaven-remote-setup-ubuntu-$RANDOM"
PORT=22224
rm -rf "$GEN"
install -d -m 700 "$GEN"
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$GEN"
}
trap cleanup EXIT

npm ci --ignore-scripts --no-audit --no-fund
npm run build
ssh-keygen -q -t ed25519 -N '' -f "$GEN/admin_id"
chmod 600 "$GEN/admin_id"
chmod 644 "$GEN/admin_id.pub"

docker build -q -t "$IMAGE" -f "$DIR/Dockerfile" "$ROOT" >/dev/null
docker run -d --name "$CONTAINER" -p "127.0.0.1:${PORT}:22" -v "$GEN/admin_id.pub:/bootstrap/admin.pub:ro" "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
  if ssh-keyscan -t ed25519 -p "$PORT" 127.0.0.1 > "$GEN/known_hosts" 2>/dev/null; then break; fi
  sleep 1
done
[[ -s "$GEN/known_hosts" ]]
chmod 644 "$GEN/known_hosts"
FINGERPRINT="$(ssh-keygen -lf "$GEN/known_hosts" -E sha256 | awk 'NR==1 {print $2}')"
[[ "$FINGERPRINT" == SHA256:* ]]
SOURCE_SHA="$(git -C "$ROOT" rev-parse HEAD)"

CLI=(node "$ROOT/dist/src/cli-entry.js")
export OPSHAVEN_HOME="$STATE"
export HOME="$GEN/home"
install -d -m 700 "$HOME"

"${CLI[@]}" init \
  --non-interactive \
  --host 127.0.0.1 \
  --port "$PORT" \
  --admin-user admin \
  --admin-identity "$GEN/admin_id" \
  --known-hosts "$GEN/known_hosts" \
  --host-key-sha256 "$FINGERPRINT" \
  --privilege sudo-noninteractive \
  --source-sha "$SOURCE_SHA" \
  > "$GEN/init.txt"
grep -q 'Local authorization keys prepared' "$GEN/init.txt"
grep -q 'opshaven setup remote' "$GEN/init.txt"
! grep -Eq 'PRIVATE KEY|BEGIN [A-Z ]+ KEY|operator-private|approval-secret' "$GEN/init.txt"

"${CLI[@]}" setup remote --non-interactive --approve --json > "$GEN/first.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || !x.installation.changed.length || !x.boundary.assertions.every(v=>v.passed)) process.exit(1)' "$GEN/first.json"

"${CLI[@]}" doctor --json > "$GEN/doctor.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.state!=="READY" || x.blocked.length) process.exit(1)' "$GEN/doctor.json"

"${CLI[@]}" boundary verify --json > "$GEN/boundary.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || !x.assertions.every(v=>v.passed)) process.exit(1)' "$GEN/boundary.json"

SSH_RESTRICTED=(ssh -p "$PORT" -i "$STATE/keys/restricted-ssh" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$GEN/known_hosts" -o ClearAllForwardings=yes -o ForwardAgent=no -o RequestTTY=no opshaven@127.0.0.1)
ORIGINAL_DENIAL="$("${SSH_RESTRICTED[@]}" id 2>&1 || true)"
[[ "$ORIGINAL_DENIAL" == *POLICY_DENIED* && "$ORIGINAL_DENIAL" != *uid=* ]]
MALFORMED="$(printf '{\n' | "${SSH_RESTRICTED[@]}")"
node -e 'const x=JSON.parse(process.argv[1]); if(x.ok || x.error?.code!=="REMOTE_PROTOCOL_INVALID") process.exit(1)' "$MALFORMED"

"${CLI[@]}" setup remote --rollback --approve --json > "$GEN/rollback.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.action!=="rollback" || (!x.restored.length && !x.removed.length)) process.exit(1)' "$GEN/rollback.json"

"${CLI[@]}" setup remote --non-interactive --approve --json > "$GEN/reinstalled.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || !x.installation.changed.length) process.exit(1)' "$GEN/reinstalled.json"
"${CLI[@]}" setup remote --non-interactive --approve --json > "$GEN/repeat.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.installation.changed.length) process.exit(1)' "$GEN/repeat.json"

"${CLI[@]}" uninstall remote --approve --json > "$GEN/uninstall.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.action!=="uninstall" || !x.removed.includes("/usr/lib/opshaven")) process.exit(1)' "$GEN/uninstall.json"
docker exec "$CONTAINER" test ! -e /usr/lib/opshaven
docker exec "$CONTAINER" test -d /home/admin

printf 'remote-setup-ubuntu: empty state, init, config-free setup, doctor, boundary verification, shell denial, rollback, reinstall, idempotent repeat, and uninstall passed\n'
