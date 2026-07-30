#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
PUBLIC_KEY_FILE="${1:?public SSH key file required}"
DISPATCHER_FILE="${2:?compiled dispatcher file required}"
CONFIG_FILE="${3:?validated remote configuration file required}"
APPROVAL_PUBLIC_KEY_FILE="${4:?approval public key file required}"

id -u opshaven >/dev/null 2>&1 || useradd --create-home --shell /bin/bash opshaven
install -d -m 700 -o opshaven -g opshaven /home/opshaven/.ssh
install -d -m 755 /etc/opshaven /usr/local/lib/opshaven
install -d -m 700 -o opshaven -g opshaven /var/lib/opshaven/remote-used
install -m 755 "$DISPATCHER_FILE" /usr/local/bin/opshaven-dispatcher
install -m 640 -o root -g opshaven "$CONFIG_FILE" /etc/opshaven/config.json
install -m 644 -o root -g root "$APPROVAL_PUBLIC_KEY_FILE" /etc/opshaven/approval-public.pem

KEY="$(cat "$PUBLIC_KEY_FILE")"
printf '%s\n' "restrict,no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding,command=\"/usr/local/bin/opshaven-dispatcher --config /etc/opshaven/config.json\" $KEY" > /home/opshaven/.ssh/authorized_keys
chown opshaven:opshaven /home/opshaven/.ssh/authorized_keys
chmod 600 /home/opshaven/.ssh/authorized_keys

echo "Restricted OpsHaven SSH account installed. Add only reviewed exact sudo rules described in docs/setup.md."
