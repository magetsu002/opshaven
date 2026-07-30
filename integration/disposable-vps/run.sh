#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="$ROOT/integration/disposable-vps"
GEN="$DIR/generated"
rm -rf "$GEN"
install -d -m 700 "$GEN" "$GEN/approvals" "$GEN/local-remote-used"

npm ci --ignore-scripts --no-audit --no-fund
npm run build

ssh-keygen -q -t ed25519 -N '' -f "$GEN/id_ed25519"
cp "$GEN/id_ed25519.pub" "$GEN/authorized_key.pub"
openssl genpkey -algorithm Ed25519 -out "$GEN/approval-private.pem" >/dev/null 2>&1
openssl pkey -in "$GEN/approval-private.pem" -pubout -out "$GEN/approval-public.pem" >/dev/null 2>&1
openssl genpkey -algorithm Ed25519 -out "$GEN/response-private.pem" >/dev/null 2>&1
openssl pkey -in "$GEN/response-private.pem" -pubout -out "$GEN/response-public.pem" >/dev/null 2>&1
openssl rand -hex 32 > "$GEN/approval.key"
chmod 600 "$GEN/id_ed25519" "$GEN/approval-private.pem" "$GEN/response-private.pem" "$GEN/approval.key"
chmod 644 "$GEN/id_ed25519.pub" "$GEN/authorized_key.pub" "$GEN/approval-public.pem" "$GEN/response-public.pem"

node --input-type=module - "$GEN" <<'NODE'
import { writeFileSync } from "node:fs";
import path from "node:path";
const root = path.resolve(process.argv[2]);
const config = {
  version: 1,
  policyVersion: "integration-v1",
  limits: { timeoutMs: 15000, maxBytes: 131072, maxLines: 1000 },
  audit: { path: path.join(root, "audit.jsonl") },
  approvals: {
    directory: path.join(root, "approvals"),
    secretFile: path.join(root, "approval.key"),
    signingPrivateKeyFile: path.join(root, "approval-private.pem"),
    verificationPublicKeyFile: path.join(root, "approval-public.pem"),
    remoteUsedDirectory: path.join(root, "local-remote-used"),
    defaultTtlSeconds: 300,
  },
  secretFingerprints: [],
  resources: [
    {
      id: "host.fixture",
      kind: "host",
      address: "127.0.0.1",
      port: 22222,
      user: "opshaven",
      knownHostsFile: path.join(root, "known_hosts"),
      identityFile: path.join(root, "id_ed25519"),
      connectTimeoutMs: 5000,
    },
    { id: "svc.fixture", kind: "service", hostId: "host.fixture", unit: "opshaven-fixture.service" },
    {
      id: "probe.fixture",
      kind: "probe",
      hostId: "host.fixture",
      url: "http://127.0.0.1:18080/health",
      method: "GET",
      expectedStatus: [200],
      timeoutMs: 3000,
    },
    {
      id: "dep.fixture",
      kind: "deployment",
      hostId: "host.fixture",
      repositoryPath: "/srv/opshaven/repository",
      releasesPath: "/srv/opshaven/releases",
      currentSymlink: "/srv/opshaven/current",
      allowedRefs: ["refs/heads/main"],
      activation: "systemd",
      serviceIds: ["svc.fixture"],
      probeIds: ["probe.fixture"],
      buildSteps: [],
      checkSteps: [],
      fetchBeforeDeploy: false,
      migrationPolicy: "none",
    },
  ],
};
writeFileSync(path.join(root, "local.config.json"), JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
NODE

cp "$GEN/response-public.pem" "$GEN/local.config.json.response-public.pem"
chmod 644 "$GEN/local.config.json.response-public.pem"
node "$DIR/generate-capability.mjs" \
  "$GEN/local.config.json" \
  "$GEN/approval-private.pem" \
  "$ROOT/dist/src/remote/dispatcher.js" \
  "$GEN/capability.json" \
  "$GEN/local.config.json.capability.json"
chmod 600 "$GEN/capability.json" "$GEN/local.config.json.capability.json"

cleanup() {
  docker compose -f "$DIR/compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$GEN"
}
trap cleanup EXIT

docker compose -f "$DIR/compose.yml" up -d --build
for _ in $(seq 1 60); do
  if [[ -s "$GEN/commits.json" ]] && docker compose -f "$DIR/compose.yml" exec -T vps systemctl is-active --quiet ssh.service opshaven-fixture.service; then
    break
  fi
  sleep 1
done
[[ -s "$GEN/commits.json" ]]
docker compose -f "$DIR/compose.yml" exec -T vps systemctl is-active --quiet ssh.service opshaven-fixture.service

for _ in $(seq 1 40); do
  if ssh-keyscan -p 22222 127.0.0.1 > "$GEN/known_hosts" 2>/dev/null; then break; fi
  sleep 1
done
[[ -s "$GEN/known_hosts" ]]
SSH=(ssh -p 22222 -i "$GEN/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$GEN/known_hosts" -o ClearAllForwardings=yes -o ForwardAgent=no -o RequestTTY=no opshaven@127.0.0.1)

SHELL_RESULT="$("${SSH[@]}" id 2>/dev/null || true)"
[[ "$SHELL_RESULT" == *'POLICY_DENIED'* ]]
[[ "$SHELL_RESULT" != *'uid='* ]]

INSPECTION="$(node "$DIR/inspect.mjs" "$GEN/local.config.json")"
node -e 'const x=JSON.parse(process.argv[1]); if(!x.ok || !x.data?.uname) process.exit(1)' "$INSPECTION"

ssh-keygen -q -t ed25519 -N '' -f "$GEN/fake_host_key"
printf '[127.0.0.1]:22222 %s\n' "$(cut -d' ' -f1,2 "$GEN/fake_host_key.pub")" > "$GEN/bad_known_hosts"
set +e
printf '{}\n' | ssh -p 22222 -i "$GEN/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$GEN/bad_known_hosts" -o ClearAllForwardings=yes -o ForwardAgent=no -o RequestTTY=no opshaven@127.0.0.1 >/dev/null 2>&1
BAD_HOST_STATUS=$?
set -e
[[ $BAD_HOST_STATUS -ne 0 ]]

UNSIGNED='{"version":1,"requestId":"integration-unsigned","operation":"get_host_summary","resourceId":"host.fixture","args":{"resourceId":"host.fixture"},"limits":{"timeoutMs":15000,"maxBytes":131072,"maxLines":1000}}'
REJECTED="$(printf '%s\n' "$UNSIGNED" | "${SSH[@]}")"
node -e 'const x=JSON.parse(process.argv[1]); if(x.ok || x.error?.code!=="REMOTE_PROTOCOL_INVALID") process.exit(1)' "$REJECTED"

LIFECYCLE="$(node "$DIR/lifecycle.mjs" "$GEN/local.config.json" "$GEN/commits.json")"
node -e 'const x=JSON.parse(process.argv[1]); if(x.dryRun!=="no-change" || !x.replayRejected || !x.argumentMutationRejected || x.auditRecords < 12) process.exit(1)' "$LIFECYCLE"
BOUNDARY="$(node "$ROOT/dist/src/cli.js" verify-boundary --config "$GEN/local.config.json" --json)"
node -e 'const x=JSON.parse(process.argv[1]); if(!x.ok || x.assertions.some((item)=>!item.passed)) process.exit(1)' "$BOUNDARY"
printf 'disposable-vps: shell denial, pinned host keys, signed capabilities, authenticated requests and responses, confinement, boundary verification, exact deployment, failed-health restoration, rollback, approval rejection, and audit verification passed\n'
