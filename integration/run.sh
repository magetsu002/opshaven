#!/bin/sh
set -eu

for executable in docker ssh ssh-keygen ssh-keyscan node; do
  if ! command -v "$executable" >/dev/null 2>&1; then
    echo "Required integration executable is missing: $executable" >&2
    exit 2
  fi
done

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
work="$(mktemp -d)"
container="opshaven-v1-$PPID-$$"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

stage() {
  printf 'integration: %s\n' "$1"
}

fail_fixture() {
  printf 'integration failure: %s\n' "$1" >&2
  docker inspect "$container" >&2 || true
  docker logs "$container" >&2 || true
  exit 1
}

cd "$root"
stage "build project and fixture image"
npm run build >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$work/id_ed25519"
public_key="$(cat "$work/id_ed25519.pub")"
docker build -f integration/Dockerfile -t opshaven-v1-integration:local . >/dev/null
docker run -d --name "$container" -p 127.0.0.1::22 \
  -e "OPSHAVEN_AUTHORIZED_KEY=$public_key" opshaven-v1-integration:local >/dev/null
port="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "22/tcp") 0).HostPort}}' "$container")"
printf 'integration: fixture port %s\n' "$port"

stage "wait for SSH host key"
attempt=0
while :; do
  if ssh-keyscan -p "$port" -t ed25519 127.0.0.1 > "$work/known_hosts.next" 2> "$work/keyscan.err" \
    && [ -s "$work/known_hosts.next" ]; then
    mv "$work/known_hosts.next" "$work/known_hosts"
    break
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    cat "$work/keyscan.err" >&2 || true
    fail_fixture "SSH host key did not become reachable"
  fi
  sleep 1
done
fingerprint="$(ssh-keygen -lf "$work/known_hosts" -E sha256 | awk 'NR == 1 { print $2 }')"

cat > "$work/client.json" <<EOF_CONFIG
{
  "version": 1,
  "policyVersion": "integration-v1",
  "defaults": { "timeoutMs": 10000, "output": { "maxBytes": 65536, "maxLines": 500 } },
  "audit": { "path": "$work/audit.jsonl" },
  "approvals": { "stateDirectory": "$work/approvals", "ttlSeconds": 300, "keyEnvironmentVariable": "OPSHAVEN_APPROVAL_KEY" },
  "secrets": { "fingerprints": ["PLANTED-INTEGRATION-FINGERPRINT"], "keyNames": ["authorization", "cookie", "password", "secret", "token"] },
  "hosts": [{
    "id": "fixture-host", "address": "127.0.0.1", "port": $port, "username": "opshaven",
    "identityFile": "$work/id_ed25519", "knownHostsFile": "$work/known_hosts",
    "hostKeySha256": "$fingerprint", "dispatcherCommand": "opshaven-dispatch", "firewallProvider": "ufw"
  }],
  "applications": [{ "id": "fixture-app", "hostId": "fixture-host", "displayName": "Generic fixture application" }],
  "services": [{
    "id": "fixture-service", "hostId": "fixture-host", "applicationId": "fixture-app", "unit": "fixture.service",
    "restartAllowed": false, "runtimeEnvFile": "/etc/opshaven/fixture.env", "requiredEnvironment": ["NODE_ENV", "SECRET_TOKEN"]
  }],
  "containers": [],
  "deployments": [{
    "id": "fixture-deployment", "hostId": "fixture-host", "applicationId": "fixture-app",
    "repositoryPath": "/srv/opshaven-fixture/repository", "releasesPath": "/srv/opshaven-fixture/releases",
    "activeSymlink": "/srv/opshaven-fixture/current", "stateFile": "/var/lib/opshaven/releases.json",
    "allowedRefs": ["refs/heads/main"], "strategy": "systemd", "serviceIds": [], "probeIds": [],
    "checkSteps": [], "buildSteps": [], "migrationRisk": "none"
  }],
  "proxies": [], "probes": [], "databases": [], "monitoring": [], "backups": []
}
EOF_CONFIG

call_tool() {
  name="$1"
  arguments="$2"
  destination="$3"
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$name\",\"arguments\":$arguments}}" \
    | node dist/index.js --config "$work/client.json" > "$destination"
}

stage "inspect host through forced dispatcher"
call_tool get_host_summary '{"hostId":"fixture-host"}' "$work/host.json"
node integration/assert-response.mjs "$work/host.json" get_host_summary true

stage "inspect deployed commit through forced dispatcher"
call_tool get_deployed_commit '{"deploymentId":"fixture-deployment"}' "$work/commit.json"
node integration/assert-response.mjs "$work/commit.json" get_deployed_commit true

stage "verify runtime metadata does not expose values"
call_tool get_runtime_config_status '{"serviceId":"fixture-service"}' "$work/runtime.json"
node integration/assert-response.mjs "$work/runtime.json" get_runtime_config_status true 'PLANTED-SECRET-MUST-NOT-CROSS-SSH'
grep -q '"valuesExposed":false' "$work/runtime.json"

stage "prove arbitrary SSH command cannot execute"
set +e
ssh -T -p "$port" -i "$work/id_ed25519" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=$work/known_hosts" -o GlobalKnownHostsFile=/dev/null \
  -- opshaven@127.0.0.1 'touch /tmp/opshaven-shell-escape' > "$work/forced.out" 2> "$work/forced.err"
ssh_status=$?
set -e
[ "$ssh_status" -ne 0 ] || fail_fixture "arbitrary SSH command unexpectedly succeeded"
! docker exec "$container" test -e /tmp/opshaven-shell-escape \
  || fail_fixture "arbitrary SSH command created a file"

stage "prove host-key mismatch fails closed"
good_fingerprint="$fingerprint"
sed "s|$good_fingerprint|SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|" "$work/client.json" > "$work/mismatch.json"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_host_summary","arguments":{"hostId":"fixture-host"}}}' \
  | node dist/index.js --config "$work/mismatch.json" > "$work/mismatch-response.json"
node integration/assert-response.mjs "$work/mismatch-response.json" get_host_summary false
grep -q 'SSH_HOST_KEY_MISMATCH' "$work/mismatch-response.json"

stage "verify audit chain"
node dist/cli.js audit verify --config "$work/client.json" > "$work/audit-verification.json"
grep -q '"valid": true' "$work/audit-verification.json"

echo "Restricted SSH integration passed on port $port"
