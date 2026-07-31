#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="$ROOT/integration/remote-setup-ubuntu"
GEN="$DIR/generated"
IMAGE="opshaven-remote-setup-ubuntu"
CONTAINER="opshaven-remote-setup-ubuntu-$RANDOM"
PORT=22224
rm -rf "$GEN"
install -d -m 700 "$GEN" "$GEN/approvals" "$GEN/local-remote-used"
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$GEN"
}
trap cleanup EXIT

npm ci --ignore-scripts --no-audit --no-fund
npm run build
ssh-keygen -q -t ed25519 -N '' -f "$GEN/admin_id"
ssh-keygen -q -t ed25519 -N '' -f "$GEN/restricted_id"
openssl genpkey -algorithm Ed25519 -out "$GEN/operator-private.pem" >/dev/null 2>&1
openssl pkey -in "$GEN/operator-private.pem" -pubout -out "$GEN/operator-public.pem" >/dev/null 2>&1
openssl rand -hex 32 > "$GEN/approval.key"
chmod 600 "$GEN/admin_id" "$GEN/restricted_id" "$GEN/operator-private.pem" "$GEN/approval.key"
chmod 644 "$GEN/admin_id.pub" "$GEN/restricted_id.pub" "$GEN/operator-public.pem"

docker build -q -t "$IMAGE" -f "$DIR/Dockerfile" "$ROOT" >/dev/null
docker run -d --name "$CONTAINER" -p "127.0.0.1:${PORT}:22" -v "$GEN/admin_id.pub:/bootstrap/admin.pub:ro" "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
  if ssh-keyscan -t ed25519 -p "$PORT" 127.0.0.1 > "$GEN/known_hosts" 2>/dev/null; then break; fi
  sleep 1
done
[[ -s "$GEN/known_hosts" ]]
FINGERPRINT="$(ssh-keygen -lf "$GEN/known_hosts" -E sha256 | awk 'NR==1 {print $2}')"
[[ "$FINGERPRINT" == SHA256:* ]]
SOURCE_SHA="$(git -C "$ROOT" rev-parse HEAD)"

node --input-type=module - "$ROOT" "$GEN" "$PORT" "$FINGERPRINT" "$SOURCE_SHA" <<'NODE'
import { chmodSync, writeFileSync } from "node:fs";
import path from "node:path";
const [root, gen, portRaw, fingerprint, sourceSha] = process.argv.slice(2);
const port = Number(portRaw);
const common = {
  version: 1,
  policyVersion: "remote-setup-ubuntu-v1",
  limits: { timeoutMs: 15000, maxBytes: 131072, maxLines: 1000 },
  secretFingerprints: [],
};
const localResources = [
  { id: "host.fixture", kind: "host", address: "127.0.0.1", port, user: "opshaven", knownHostsFile: path.join(gen, "known_hosts"), identityFile: path.join(gen, "restricted_id"), connectTimeoutMs: 5000 },
  { id: "app.fixture", kind: "application", hostId: "host.fixture", runtimeConfigKeys: ["NODE_ENV"] },
  { id: "svc.fixture", kind: "service", hostId: "host.fixture", unit: "ssh.service" },
  { id: "probe.fixture", kind: "probe", hostId: "host.fixture", url: "http://127.0.0.1:18080/health", method: "GET", expectedStatus: [200], timeoutMs: 3000 },
  { id: "dep.fixture", kind: "deployment", hostId: "host.fixture", repositoryPath: "/srv/opshaven/repository", releasesPath: "/srv/opshaven/releases", currentSymlink: "/srv/opshaven/current", allowedRefs: ["refs/heads/main"], activation: "systemd", serviceIds: ["svc.fixture"], probeIds: ["probe.fixture"], buildSteps: [], checkSteps: [], fetchBeforeDeploy: false, migrationPolicy: "none" },
  { id: "proxy.fixture", kind: "proxy", hostId: "host.fixture", provider: "nginx", serviceId: "svc.fixture", publicNames: ["fixture.example.test"] },
  { id: "monitor.fixture", kind: "monitoring", hostId: "host.fixture", serviceIds: ["svc.fixture"], probeIds: ["probe.fixture"] },
  { id: "backup.fixture", kind: "backup", hostId: "host.fixture", statusFile: "/var/lib/opshaven/backup-status.json", maximumAgeHours: 24 },
];
const remoteResources = [
  { id: "host.fixture", kind: "host", address: "localhost", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/unused-known-hosts", identityFile: "/etc/opshaven/unused-identity", connectTimeoutMs: 5000 },
  { id: "app.fixture", kind: "application", hostId: "host.fixture", runtimeConfigKeys: ["NODE_ENV"] },
  { id: "svc.fixture", kind: "service", hostId: "host.fixture", unit: "ssh.service" },
  { id: "probe.fixture", kind: "probe", hostId: "host.fixture", url: "http://127.0.0.1:18080/health", method: "GET", expectedStatus: [200], timeoutMs: 3000 },
  { id: "dep.fixture", kind: "deployment", hostId: "host.fixture", repositoryPath: "/srv/opshaven/repository", releasesPath: "/srv/opshaven/releases", currentSymlink: "/srv/opshaven/current", allowedRefs: ["refs/heads/main"], activation: "systemd", serviceIds: ["svc.fixture"], probeIds: ["probe.fixture"], buildSteps: [], checkSteps: [], fetchBeforeDeploy: false, migrationPolicy: "none" },
  { id: "proxy.fixture", kind: "proxy", hostId: "host.fixture", provider: "nginx", serviceId: "svc.fixture", publicNames: ["fixture.example.test"] },
  { id: "monitor.fixture", kind: "monitoring", hostId: "host.fixture", serviceIds: ["svc.fixture"], probeIds: ["probe.fixture"] },
  { id: "backup.fixture", kind: "backup", hostId: "host.fixture", statusFile: "/var/lib/opshaven/backup-status.json", maximumAgeHours: 24 },
];
const localConfig = {
  ...common,
  audit: { path: path.join(gen, "audit.jsonl") },
  approvals: {
    directory: path.join(gen, "approvals"),
    secretFile: path.join(gen, "approval.key"),
    signingPrivateKeyFile: path.join(gen, "operator-private.pem"),
    verificationPublicKeyFile: path.join(gen, "operator-public.pem"),
    remoteUsedDirectory: path.join(gen, "local-remote-used"),
    defaultTtlSeconds: 300,
  },
  resources: localResources,
};
const remoteConfig = {
  ...common,
  audit: { path: "/var/lib/opshaven/audit.jsonl" },
  approvals: {
    directory: "/var/lib/opshaven/unused-approvals",
    secretFile: "/var/lib/opshaven/unused-secret",
    signingPrivateKeyFile: "/var/lib/opshaven/unused-private",
    verificationPublicKeyFile: "/etc/opshaven/approval-public.pem",
    remoteUsedDirectory: "/var/lib/opshaven/remote-used",
    defaultTtlSeconds: 300,
  },
  resources: remoteResources,
};
const policyPath = path.join(gen, "config.json");
const setup = {
  version: 1,
  policyConfigPath: policyPath,
  expectedSourceSha: sourceSha,
  target: {
    host: "127.0.0.1",
    port,
    adminUser: "admin",
    knownHostsFile: path.join(gen, "known_hosts"),
    identityFile: path.join(gen, "admin_id"),
    expectedHostKeySha256: fingerprint,
    privilege: "sudo-noninteractive",
  },
  local: {
    runtimeRoot: path.join(root, "dist-readonly"),
    dispatcherPath: path.join(root, "dist-readonly/src/remote/read-only-dispatcher.js"),
    wrapperTemplatePath: path.join(root, "packaging/opshaven-readonly-force-command"),
    capabilityDeclarationPath: path.join(root, "security/capability-declaration.json"),
    operatorPrivateKeyFile: path.join(gen, "operator-private.pem"),
    operatorPublicKeyFile: path.join(gen, "operator-public.pem"),
    restrictedAuthorizedKeyFile: path.join(gen, "restricted_id.pub"),
  },
  remote: {
    account: "opshaven",
    runtimeRoot: "/usr/lib/opshaven",
    configPath: "/etc/opshaven/config.json",
    wrapperPath: "/usr/local/bin/opshaven-readonly-force-command",
    stateDirectory: "/var/lib/opshaven",
    receiptPath: "/var/lib/opshaven/setup-receipt.json",
    nodeCandidates: ["/usr/local/bin/node"],
  },
  trust: { expiresInSeconds: 3600 },
};
writeFileSync(policyPath, JSON.stringify(localConfig, null, 2) + "\n", { mode: 0o600 });
writeFileSync(`${policyPath}.dispatcher.json`, JSON.stringify(remoteConfig, null, 2) + "\n", { mode: 0o600 });
writeFileSync(path.join(gen, "setup.json"), JSON.stringify(setup, null, 2) + "\n", { mode: 0o600 });
chmodSync(path.join(gen, "known_hosts"), 0o644);
NODE

CLI=(node "$ROOT/dist/src/cli.js")
SETUP=(setup remote --non-interactive --approve --config "$GEN/setup.json" --json)
"${CLI[@]}" "${SETUP[@]}" > "$GEN/first.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || !x.installation.changed.length || !x.boundary.assertions.every(v=>v.passed)) process.exit(1)' "$GEN/first.json"

SSH_RESTRICTED=(ssh -p "$PORT" -i "$GEN/restricted_id" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$GEN/known_hosts" -o ClearAllForwardings=yes -o ForwardAgent=no -o RequestTTY=no opshaven@127.0.0.1)
ORIGINAL_DENIAL="$("${SSH_RESTRICTED[@]}" id 2>&1 || true)"
[[ "$ORIGINAL_DENIAL" == *POLICY_DENIED* && "$ORIGINAL_DENIAL" != *uid=* ]]
MALFORMED="$(printf '{\n' | "${SSH_RESTRICTED[@]}")"
node -e 'const x=JSON.parse(process.argv[1]); if(x.ok || x.error?.code!=="REMOTE_PROTOCOL_INVALID") process.exit(1)' "$MALFORMED"

"${CLI[@]}" setup remote --rollback --approve --config "$GEN/setup.json" --json > "$GEN/rollback.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.action!=="rollback" || (!x.restored.length && !x.removed.length)) process.exit(1)' "$GEN/rollback.json"

"${CLI[@]}" "${SETUP[@]}" > "$GEN/reinstalled.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || !x.installation.changed.length) process.exit(1)' "$GEN/reinstalled.json"
"${CLI[@]}" "${SETUP[@]}" > "$GEN/repeat.json"
node -e 'const x=require(process.argv[1]); if(!x.certified || x.installation.changed.length) process.exit(1)' "$GEN/repeat.json"

"${CLI[@]}" uninstall remote --approve --config "$GEN/setup.json" --json > "$GEN/uninstall.json"
node -e 'const x=require(process.argv[1]); if(!x.ok || x.action!=="uninstall" || !x.removed.includes("/usr/lib/opshaven")) process.exit(1)' "$GEN/uninstall.json"
docker exec "$CONTAINER" test ! -e /usr/lib/opshaven
docker exec "$CONTAINER" test -d /home/admin

printf 'remote-setup-ubuntu: first install, boundary certification, shell denial, malformed input, rollback, reinstall, idempotent repeat, and conservative uninstall passed\n'
