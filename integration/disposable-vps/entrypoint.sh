#!/usr/bin/env bash
set -euo pipefail

install -d -m 755 /run/sshd
ssh-keygen -A
systemd-machine-id-setup >/dev/null 2>&1 || true

KEY_FILE=/run/opshaven-test/authorized_key.pub
PUBLIC_KEY_FILE=/run/opshaven-test/approval-public.pem
CAPABILITY_FILE=/run/opshaven-test/capability.json
RESPONSE_PRIVATE_FILE=/run/opshaven-test/response-private.pem
if [[ ! -s "$KEY_FILE" || ! -s "$PUBLIC_KEY_FILE" || ! -s "$CAPABILITY_FILE" || ! -s "$RESPONSE_PRIVATE_FILE" ]]; then
  echo "Missing disposable test trust material." >&2
  exit 1
fi

KEY="$(cat "$KEY_FILE")"
printf '%s\n' "restrict,no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding,command=\"/usr/local/bin/opshaven-dispatcher --config /etc/opshaven/config.json\" $KEY" > /home/opshaven/.ssh/authorized_keys
chown opshaven:opshaven /home/opshaven/.ssh/authorized_keys
chmod 600 /home/opshaven/.ssh/authorized_keys
install -o root -g root -m 644 "$PUBLIC_KEY_FILE" /etc/opshaven/approval-public.pem
install -o root -g root -m 644 "$CAPABILITY_FILE" /etc/opshaven/config.json.capability.json
install -o root -g opshaven -m 640 "$RESPONSE_PRIVATE_FILE" /etc/opshaven/config.json.response-private.pem

rm -rf /srv/opshaven/repository /srv/opshaven/releases /srv/opshaven/current
install -d -m 755 -o opshaven -g opshaven /srv/opshaven/repository /srv/opshaven/releases

runuser -u opshaven -- git -C /srv/opshaven/repository init -b main >/dev/null
runuser -u opshaven -- git -C /srv/opshaven/repository config user.name "OpsHaven Fixture"
runuser -u opshaven -- git -C /srv/opshaven/repository config user.email "fixture@example.invalid"

commit_fixture() {
  local version="$1"
  local status="$2"
  local date="$3"
  printf '%s\n' "$version" > /srv/opshaven/repository/version.txt
  printf '%s\n' "$status" > /srv/opshaven/repository/status.txt
  chown opshaven:opshaven /srv/opshaven/repository/version.txt /srv/opshaven/repository/status.txt
  runuser -u opshaven -- git -C /srv/opshaven/repository add version.txt status.txt
  runuser -u opshaven -- env GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" git -C /srv/opshaven/repository commit -m "fixture: $version" >/dev/null
  runuser -u opshaven -- git -C /srv/opshaven/repository rev-parse HEAD
}

COMMIT_A="$(commit_fixture release-a 200 '2026-01-01T00:00:00Z')"
COMMIT_B="$(commit_fixture release-b 200 '2026-01-02T00:00:00Z')"
COMMIT_C="$(commit_fixture release-c 503 '2026-01-03T00:00:00Z')"

INITIAL_RELEASE=/srv/opshaven/releases/release-initial
runuser -u opshaven -- git -C /srv/opshaven/repository worktree add --detach "$INITIAL_RELEASE" "$COMMIT_A" >/dev/null
ln -s "$INITIAL_RELEASE" /srv/opshaven/current

python3 - "$COMMIT_A" "$INITIAL_RELEASE" <<'PY'
import json
import pathlib
import sys
record = {
    "releaseId": "release-initial",
    "commit": sys.argv[1],
    "path": sys.argv[2],
    "activatedAt": "2026-01-01T00:00:00.000Z",
    "previousPath": None,
    "status": "active",
    "migrationPolicy": "none",
}
path = pathlib.Path("/srv/opshaven/releases/opshaven-releases.jsonl")
path.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
PY
chown -R opshaven:opshaven /srv/opshaven
chmod 600 /srv/opshaven/releases/opshaven-releases.jsonl

python3 - "$COMMIT_A" "$COMMIT_B" "$COMMIT_C" <<'PY'
import json
import pathlib
import sys
pathlib.Path("/run/opshaven-test/commits.json").write_text(
    json.dumps({"a": sys.argv[1], "b": sys.argv[2], "c": sys.argv[3]}, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
chmod 644 /run/opshaven-test/commits.json

exec /sbin/init
