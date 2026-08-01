#!/usr/bin/env bash
set -euo pipefail
on_error() {
  local status=$?
  trap - ERR
  printf 'remote-setup-ubuntu failed at line %s\n' "$1" >&2
  exit "$status"
}
trap 'on_error "$LINENO"' ERR
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="$ROOT/integration/remote-setup-ubuntu"
GEN="$DIR/generated"
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
milliseconds() { node -e 'process.stdout.write(String(Date.now()))'; }
elapsed() { printf '%s' "$(( $(milliseconds) - $1 ))"; }

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
API_REVISION="$(docker exec "$CONTAINER" git -C /srv/opshaven-fixtures/sample-api/repository rev-parse HEAD)"
[[ "$API_REVISION" =~ ^[0-9a-f]{40}$ ]]

CLI=(node "$ROOT/dist/src/cli-entry.js")
export HOME="$GEN/home"
STATE="$HOME/.config/opshaven"
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
grep -q 'opshaven app add' "$GEN/init.txt"
! grep -Eq 'PRIVATE KEY|BEGIN [A-Z ]+ KEY|operator-private|approval-secret' "$GEN/init.txt"

"${CLI[@]}" app add \
  --non-interactive --approve --json \
  --id sample-api --name 'Sample API' --target host.primary \
  --repository /srv/opshaven-fixtures/sample-api/repository \
  --releases /srv/opshaven-fixtures/sample-api/releases \
  --service sample-api.service \
  --health-check http://127.0.0.1:3000/health \
  > "$GEN/app-api.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.application?.id!=="sample-api") process.exit(1)' "$GEN/app-api.json"

FULL_STARTED="$(milliseconds)"
"${CLI[@]}" setup remote --non-interactive --approve --json > "$GEN/first.json"
FULL_MS="$(elapsed "$FULL_STARTED")"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.outcome!=="SETUP_SUCCEEDED" || x.changeType!=="FULL_INSTALL" || !x.installation?.changed?.length || !x.boundary.assertions.every(v=>v.passed) || !x.canonicalState?.compatible || !["COMMIT","CLEANUP"].includes(x.transaction?.phase)) process.exit(1)' "$GEN/first.json"
FULL_GENERATION="$(node -e 'process.stdout.write(String(require(process.argv[1]).canonicalState.installed.generation))' "$GEN/first.json")"
[[ "$FULL_MS" -lt 180000 ]]

"${CLI[@]}" doctor --json > "$GEN/doctor.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.state!=="READY" || x.blocked.length) process.exit(1)' "$GEN/doctor.json"
"${CLI[@]}" boundary verify --json > "$GEN/boundary.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || !x.assertions.every(v=>v.passed) || !x.canonicalState || x.canonicalState.result!=="compatible" || x.synchronizationTransaction?.status!=="resolved") process.exit(1)' "$GEN/boundary.json"
"${CLI[@]}" deploy plan sample-api --revision "$API_REVISION" --json > "$GEN/plan.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || !x.planId?.startsWith("sha256:") || x.plan?.targetRevision!==process.argv[2]) process.exit(1)' "$GEN/plan.json" "$API_REVISION"

SSH_RESTRICTED=(ssh -p "$PORT" -i "$STATE/keys/restricted-ssh" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$GEN/known_hosts" -o ClearAllForwardings=yes -o ForwardAgent=no -o RequestTTY=no opshaven@127.0.0.1)
ORIGINAL_DENIAL="$("${SSH_RESTRICTED[@]}" id 2>&1 || true)"
[[ "$ORIGINAL_DENIAL" == *POLICY_DENIED* && "$ORIGINAL_DENIAL" != *uid=* ]]
MALFORMED="$(printf '{\n' | "${SSH_RESTRICTED[@]}")"
node -e 'const x=JSON.parse(process.argv[1]); if(x.ok || x.error?.code!=="REMOTE_PROTOCOL_INVALID") process.exit(1)' "$MALFORMED"

"${CLI[@]}" app add \
  --non-interactive --approve --json \
  --id sample-worker --name 'Sample Worker' --target host.primary \
  --repository /srv/opshaven-fixtures/sample-worker/repository \
  --releases /srv/opshaven-fixtures/sample-worker/releases \
  --service sample-worker.service \
  --health-check http://127.0.0.1:3001/health \
  > "$GEN/app-worker.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.application?.id!=="sample-worker") process.exit(1)' "$GEN/app-worker.json"

AUTH_STARTED="$(milliseconds)"
"${CLI[@]}" setup remote --non-interactive --approve --json > "$GEN/authorization.json"
AUTH_MS="$(elapsed "$AUTH_STARTED")"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.outcome!=="SETUP_SUCCEEDED" || x.changeType!=="AUTHORIZATION_ONLY" || x.installation || x.trust?.synchronizationKind!=="authorization-sync" || !x.canonicalState?.compatible) process.exit(1)' "$GEN/authorization.json"
AUTH_GENERATION="$(node -e 'process.stdout.write(String(require(process.argv[1]).canonicalState.installed.generation))' "$GEN/authorization.json")"
[[ "$AUTH_GENERATION" -eq $((FULL_GENERATION + 1)) ]]
[[ "$AUTH_MS" -lt 20000 ]]

# Roll back the authorization-only update to the previous verified generation.
"${CLI[@]}" setup remote --rollback --approve --json > "$GEN/authorization-rollback.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.action!=="rollback" || !x.restored.length) process.exit(1)' "$GEN/authorization-rollback.json"
"${CLI[@]}" setup remote --non-interactive --approve --json > "$GEN/authorization-reapplied.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.changeType!=="AUTHORIZATION_ONLY" || x.installation || x.trust?.synchronizationKind!=="authorization-sync" || !x.canonicalState?.compatible) process.exit(1)' "$GEN/authorization-reapplied.json"
REAPPLIED_GENERATION="$(node -e 'process.stdout.write(String(require(process.argv[1]).canonicalState.installed.generation))' "$GEN/authorization-reapplied.json")"
[[ "$REAPPLIED_GENERATION" -eq "$AUTH_GENERATION" ]]

NO_CHANGE_STARTED="$(milliseconds)"
"${CLI[@]}" setup remote --non-interactive --approve --json > "$GEN/no-change.json"
NO_CHANGE_MS="$(elapsed "$NO_CHANGE_STARTED")"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.outcome!=="SETUP_NO_CHANGE" || x.changeType!=="NO_CHANGE" || x.installation || x.trust || !x.canonicalState?.compatible) process.exit(1)' "$GEN/no-change.json"
NO_CHANGE_GENERATION="$(node -e 'process.stdout.write(String(require(process.argv[1]).canonicalState.installed.generation))' "$GEN/no-change.json")"
RUNTIME_CORE_BEFORE="$(node -e 'process.stdout.write(require(process.argv[1]).canonicalState.installed.runtimeSha256)' "$GEN/no-change.json")"
[[ "$NO_CHANGE_GENERATION" -eq "$REAPPLIED_GENERATION" ]]
[[ "$NO_CHANGE_MS" -lt 10000 ]]

"${CLI[@]}" doctor --json > "$GEN/doctor-after-sync.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.state!=="READY") process.exit(1)' "$GEN/doctor-after-sync.json"

# Deliberately replace the active reviewed dispatcher with the valid legacy artifact.
docker exec "$CONTAINER" sh -c 'cp /usr/lib/opshaven/src/remote/read-only-dispatcher.js /usr/lib/opshaven/src/remote/dispatcher.js && chmod 755 /usr/lib/opshaven/src/remote/dispatcher.js'
if "${CLI[@]}" doctor --debug --json > "$GEN/mismatch-doctor.json" 2> "$GEN/mismatch-doctor.err"; then DOCTOR_STATUS=0; else DOCTOR_STATUS=$?; fi
if "${CLI[@]}" boundary verify --json > "$GEN/mismatch-boundary.json" 2> "$GEN/mismatch-boundary.err"; then BOUNDARY_STATUS=0; else BOUNDARY_STATUS=$?; fi
[[ "$DOCTOR_STATUS" -ne 0 && "$BOUNDARY_STATUS" -ne 0 ]]
node -e 'const x=require(process.argv[1]); const d=x.details?.deploymentCompatibility; if(x.ok || !d || d.expectedDispatcherDigest===d.installedDispatcherDigest || d.repair!=="opshaven setup remote") process.exit(1)' "$GEN/mismatch-doctor.json"
grep -Eq 'Remote boundary certification failed|Authorization setup is incomplete|Security boundary' "$GEN/mismatch-boundary.err"

DISPATCHER_STARTED="$(milliseconds)"
"${CLI[@]}" setup remote --non-interactive --approve --json > "$GEN/dispatcher-repair.json"
DISPATCHER_MS="$(elapsed "$DISPATCHER_STARTED")"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.changeType!=="DISPATCHER_AND_AUTHORIZATION" || x.installation || x.dispatcherInstallation?.dependencyInstall!==false || x.trust?.synchronizationKind!=="authorization-sync" || x.timings?.runtimeInstallation!==undefined || !x.canonicalState?.compatible || !["COMMIT","CLEANUP"].includes(x.transaction?.phase)) process.exit(1)' "$GEN/dispatcher-repair.json"
RUNTIME_CORE_AFTER="$(node -e 'process.stdout.write(require(process.argv[1]).canonicalState.installed.runtimeSha256)' "$GEN/dispatcher-repair.json")"
[[ "$RUNTIME_CORE_AFTER" == "$RUNTIME_CORE_BEFORE" ]]
[[ "$DISPATCHER_MS" -lt 20000 ]]

"${CLI[@]}" doctor --json > "$GEN/repaired-doctor.json"
"${CLI[@]}" boundary verify --json > "$GEN/repaired-boundary.json"
node -e 'const d=require(process.argv[1]); const b=require(process.argv[2]); if(!d.ok || d.state!=="READY" || !b.ok || !b.assertions.every(v=>v.passed) || b.synchronizationTransaction?.status!=="resolved") process.exit(1)' "$GEN/repaired-doctor.json" "$GEN/repaired-boundary.json"
"${CLI[@]}" deploy plan sample-api --revision "$API_REVISION" --json > "$GEN/repaired-plan.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.plan?.targetRevision!==process.argv[2]) process.exit(1)' "$GEN/repaired-plan.json" "$API_REVISION"

"${CLI[@]}" uninstall remote --approve --json > "$GEN/uninstall.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.action!=="uninstall" || !x.removed.includes("/usr/lib/opshaven")) process.exit(1)' "$GEN/uninstall.json"
docker exec "$CONTAINER" test ! -e /usr/lib/opshaven
docker exec "$CONTAINER" test -d /home/admin

printf 'remote-setup-ubuntu timings_ms full=%s authorization=%s no_change=%s dispatcher=%s\n' "$FULL_MS" "$AUTH_MS" "$NO_CHANGE_MS" "$DISPATCHER_MS"
printf 'remote-setup-ubuntu: one-pass setup, deployment plan, authorization rollback/resync, no-change verification, dispatcher-only repair without dependency installation, and uninstall passed\n'
