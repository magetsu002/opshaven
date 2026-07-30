#!/bin/sh
set -eu

ACCOUNT="opshaven"
HOME_DIR="/var/lib/opshaven"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi

if ! id "$ACCOUNT" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$HOME_DIR" --shell /bin/sh "$ACCOUNT"
fi
# A leading ! locks the account and makes sshd reject public-key authentication.
# * is not a valid password hash, so password login remains impossible while key-only forced commands work.
usermod --password '*' "$ACCOUNT"
install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0700 "$HOME_DIR/.ssh"
install -d -o root -g "$ACCOUNT" -m 0750 /etc/opshaven
install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0750 "$HOME_DIR/state"

echo "Install the dedicated public key with the forced-command restrictions from deploy/sshd/."
echo "Install the Match User sshd fragment, validate with sshd -t, then reload sshd."
echo "Install only exact-unit sudo rules generated for configured restartable services."
