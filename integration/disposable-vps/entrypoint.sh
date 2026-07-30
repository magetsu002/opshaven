#!/usr/bin/env bash
set -euo pipefail
ssh-keygen -A
KEY_FILE=/run/opshaven-test/authorized_key.pub
if [[ ! -s "$KEY_FILE" ]]; then
  echo "Missing disposable test public key." >&2
  exit 1
fi
KEY="$(cat "$KEY_FILE")"
printf '%s\n' "restrict,no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding,command=\"/usr/local/bin/opshaven-dispatcher --config /etc/opshaven/config.json\" $KEY" > /home/opshaven/.ssh/authorized_keys
chown opshaven:opshaven /home/opshaven/.ssh/authorized_keys
chmod 600 /home/opshaven/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e
