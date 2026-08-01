#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
DIR="$ROOT/integration/remote-setup-ubuntu"
WORK="$(mktemp -d)"
IMAGE="opshaven-clean-room"
CONTAINER="opshaven-clean-room-$RANDOM"
PORT=$((23000 + RANDOM % 1000))
STARTED_AT="$(date +%s)"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

cd "$ROOT"
npm ci --ignore-scripts --no-audit --no-fund
npm run install:local
hash -r
command -v opshaven >/dev/null
command -v opshaven-mcp >/dev/null
opshaven --version | grep -Eq '^OpsHaven 1\.0\.0$'
opshaven-mcp --version | grep -Eq '^OpsHaven MCP 1\.0\.0$'

ssh-keygen -q -t ed25519 -N '' -f "$WORK/admin_id"
chmod 600 "$WORK/admin_id"
chmod 644 "$WORK/admin_id.pub"
docker build -q -t "$IMAGE" -f "$DIR/Dockerfile" "$ROOT" >/dev/null
docker run -d --name "$CONTAINER" -p "127.0.0.1:${PORT}:22" -v "$WORK/admin_id.pub:/bootstrap/admin.pub:ro" "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
  if ssh-keyscan -t ed25519 -p "$PORT" 127.0.0.1 > "$WORK/known_hosts" 2>/dev/null; then break; fi
  sleep 1
done
[[ -s "$WORK/known_hosts" ]]
chmod 644 "$WORK/known_hosts"
FINGERPRINT="$(ssh-keygen -lf "$WORK/known_hosts" -E sha256 | awk 'NR==1 {print $2}')"
SOURCE_SHA="$(git -C "$ROOT" rev-parse HEAD)"

export HOME="$WORK/home"
install -d -m 700 "$HOME"

opshaven init \
  --non-interactive \
  --host 127.0.0.1 \
  --port "$PORT" \
  --admin-user admin \
  --admin-identity "$WORK/admin_id" \
  --known-hosts "$WORK/known_hosts" \
  --host-key-sha256 "$FINGERPRINT" \
  --privilege sudo-noninteractive \
  --source-sha "$SOURCE_SHA" \
  > "$WORK/init.txt"
grep -q 'Local authorization keys prepared' "$WORK/init.txt"

opshaven app add \
  --non-interactive --approve --json \
  --id sample-api --name 'Sample API' --target host.primary \
  --repository /srv/opshaven-fixtures/sample-api/repository \
  --releases /srv/opshaven-fixtures/sample-api/releases \
  --service sample-api.service \
  --health-check http://127.0.0.1:3000/health \
  > "$WORK/app.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.application?.id!=="sample-api") process.exit(1)' "$WORK/app.json"

opshaven setup remote --non-interactive --approve --json > "$WORK/setup.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.changeType!=="FULL_INSTALL" || !x.canonicalState?.compatible) process.exit(1)' "$WORK/setup.json"
opshaven doctor --json > "$WORK/doctor.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.state!=="READY") process.exit(1)' "$WORK/doctor.json"
opshaven boundary verify --json > "$WORK/boundary.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || !x.assertions.every(v=>v.passed)) process.exit(1)' "$WORK/boundary.json"

# Create one synthetic immutable application revision after the initial active release.
docker exec "$CONTAINER" sh -ceu '
  git -C /srv/opshaven-fixtures/sample-api/repository config user.name "OpsHaven Synthetic Fixture"
  git -C /srv/opshaven-fixtures/sample-api/repository config user.email "fixture@example.invalid"
  printf "healthy revision\n" > /srv/opshaven-fixtures/sample-api/repository/REVISION.txt
  git -C /srv/opshaven-fixtures/sample-api/repository add REVISION.txt
  git -C /srv/opshaven-fixtures/sample-api/repository commit -q -m "OpsHaven clean-room healthy revision"
'
TARGET_REVISION="$(docker exec "$CONTAINER" git -C /srv/opshaven-fixtures/sample-api/repository rev-parse HEAD)"
[[ "$TARGET_REVISION" =~ ^[0-9a-f]{40}$ ]]
opshaven deploy plan sample-api --revision "$TARGET_REVISION" --json > "$WORK/plan.json"
PLAN_ID="$(node -e 'const x=require(process.argv[1]); if(!x.ok || !x.planId) process.exit(1); process.stdout.write(x.planId)' "$WORK/plan.json")"

# A pseudo-terminal exercises the same explicit interactive approval shown to an operator.
printf 'y\n' | script -qefc "opshaven deploy apply '$PLAN_ID' --json" "$WORK/apply.typescript" > "$WORK/apply.console"
tr -d '\r' < "$WORK/apply.console" | tail -n 1 > "$WORK/apply.json"
node -e 'const x=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8")); if(!x.ok || x.result?.outcome!=="DEPLOYMENT_SUCCEEDED" || x.result?.activeRevision!==process.argv[2]) process.exit(1)' "$WORK/apply.json" "$TARGET_REVISION"
opshaven doctor --json > "$WORK/post-apply-doctor.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.state!=="READY") process.exit(1)' "$WORK/post-apply-doctor.json"
opshaven setup remote --non-interactive --approve --json > "$WORK/no-change.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.changeType!=="NO_CHANGE" || x.outcome!=="SETUP_NO_CHANGE") process.exit(1)' "$WORK/no-change.json"

# Reproduce the real damaged baseline: managed state remains but the setup receipt is missing.
docker exec "$CONTAINER" rm -f /var/lib/opshaven/setup-receipt.json
set +e
opshaven setup remote --non-interactive --approve > "$WORK/blocked.out" 2> "$WORK/blocked.err"
BLOCKED_STATUS=$?
opshaven doctor --debug --json > "$WORK/damaged-doctor.json" 2> "$WORK/damaged-doctor.err"
DOCTOR_STATUS=$?
opshaven setup repair --json > "$WORK/repair-plan.json" 2> "$WORK/repair-plan.err"
REPAIR_STATUS=$?
set -e
[[ "$BLOCKED_STATUS" -ne 0 && "$DOCTOR_STATUS" -ne 0 && "$REPAIR_STATUS" -ne 0 ]]
! grep -Eq 'Traceback|RuntimeError|/tmp/' "$WORK/blocked.out" "$WORK/blocked.err" "$WORK/damaged-doctor.err" "$WORK/repair-plan.err"
node -e 'const x=require(process.argv[1]); if(x.primary!=="REMOTE_GENERATION_PARTIAL" || x.repairClassification!=="EVIDENCE_PRESERVING_REINSTALL" || x.nextAction!=="opshaven setup repair") process.exit(1)' "$WORK/damaged-doctor.json"
node -e 'const x=require(process.argv[1]); if(x.action!=="clean-reinstall-required" || !x.evidencePreserved) process.exit(1)' "$WORK/repair-plan.json"

opshaven setup repair --clean-reinstall --approve --json > "$WORK/repaired.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.action!=="clean-reinstall" || !x.evidence?.evidenceManifestSha256 || !x.setup?.certified) process.exit(1)' "$WORK/repaired.json"
opshaven doctor --json > "$WORK/repaired-doctor.json"
opshaven boundary verify --json > "$WORK/repaired-boundary.json"
node -e 'const d=require(process.argv[1]); const b=require(process.argv[2]); if(!d.ok || d.state!=="READY" || !b.ok) process.exit(1)' "$WORK/repaired-doctor.json" "$WORK/repaired-boundary.json"

npm run build
hash -r
opshaven --version | grep -Eq '^OpsHaven 1\.0\.0$'
opshaven-mcp --version | grep -Eq '^OpsHaven MCP 1\.0\.0$'

ELAPSED="$(( $(date +%s) - STARTED_AT ))"
printf 'clean-room workflow: installed CLI, init, app registration, setup, doctor, boundary, exact plan/apply, no-change, partial-state diagnosis, evidence-preserving repair, and rebuild passed in %ss\n' "$ELAPSED"
