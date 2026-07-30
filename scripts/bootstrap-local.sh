#!/usr/bin/env bash
set -euo pipefail
umask 077

CONFIG_DIR="${1:-$HOME/.config/opshaven}"
STATE_DIR="${2:-$HOME/.local/state/opshaven}"
install -d -m 700 "$CONFIG_DIR" "$STATE_DIR" "$STATE_DIR/approvals" "$STATE_DIR/remote-used"

if [[ ! -f "$STATE_DIR/approval.key" ]]; then
  head -c 64 /dev/urandom > "$STATE_DIR/approval.key"
  chmod 600 "$STATE_DIR/approval.key"
fi
if [[ ! -f "$STATE_DIR/approval-private.pem" ]]; then
  openssl genpkey -algorithm ED25519 -out "$STATE_DIR/approval-private.pem"
  openssl pkey -in "$STATE_DIR/approval-private.pem" -pubout -out "$CONFIG_DIR/approval-public.pem"
  chmod 600 "$STATE_DIR/approval-private.pem"
  chmod 644 "$CONFIG_DIR/approval-public.pem"
fi

printf 'Local protected state initialized. Copy examples/local.config.json and replace only generic placeholders.\n'
