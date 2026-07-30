# Setup

This guide connects a local OpsHaven MCP server to a restricted Linux VPS.

## Requirements

You need Node.js 22 or newer, SSH access to the VPS, and a dedicated non-root VPS account.

Clone the repository, install dependencies, and verify the project:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
```

## Initialize local state

Create protected configuration, approval, and audit directories:

```bash
scripts/bootstrap-local.sh \
  "$HOME/.config/opshaven" \
  "$HOME/.local/state/opshaven"
```

Copy and edit the example configuration:

```bash
cp examples/local.config.json \
  "$HOME/.config/opshaven/config.json"
```

Use logical resource IDs and trusted absolute paths. Services, deployments, probes, logs, and other resources must be declared before an agent can access them.

## Pin the VPS host key

Collect the key into a temporary file:

```bash
ssh-keyscan -H your-host.example \
  > "$HOME/.config/opshaven/known_hosts.pending"
```

Verify the fingerprint through a separate trusted channel, then install it:

```bash
mv "$HOME/.config/opshaven/known_hosts.pending" \
  "$HOME/.config/opshaven/known_hosts"
```

Do not use automatic host-key acceptance for production systems.

## Install the restricted dispatcher

Build OpsHaven and copy the compiled dispatcher, validated remote configuration, restricted SSH public key, and approval public key to the VPS. Then run:

```bash
sudo scripts/bootstrap-remote.sh \
  /path/to/restricted-key.pub \
  /path/to/opshaven-dispatcher \
  /path/to/remote-config.json \
  /path/to/approval-public.pem
```

The script creates the restricted account and forced-command boundary. Test that an attempted custom SSH command returns a policy denial instead of a shell.

## Configure privileged operations

Add only exact sudo rules required by configured operations. Start from [the sudoers example](sudoers.example) and create one reviewed rule per allowed systemd unit.

Do not permit wildcards, shells, editors, package managers, arbitrary environment assignment, or unrestricted `systemctl` access.

For containers, prefer rootless Docker owned by the restricted account. Do not add the account to a root-equivalent system Docker socket group.

## Validate and connect

Run:

```bash
opshaven validate-config \
  --config "$HOME/.config/opshaven/config.json"

opshaven diagnostics \
  --config "$HOME/.config/opshaven/config.json"

opshaven print-mcp-config \
  --config "$HOME/.config/opshaven/config.json"
```

Add the generated entry to the MCP client configuration. OpsHaven must remain a local stdio process; do not expose it through HTTP or a public socket.

## Test safe operation

Begin with read-only operations and confirm responses refer only to configured resources. Test a mutation in dry-run mode and verify it reports `changed: false`.

A human should create an approval only after reviewing the exact target, expected state, operation digest, and expiry. Failed, expired, replayed, state-drifted, or modified approvals require a new review.

Deployments accept exact full commit IDs under configured refs and refuse dirty state or expected-current mismatches. Failed health verification restores the previous activation. Rollback accepts only releases recorded in the release ledger. Database migrations are not reversed automatically.

Verify the audit chain after testing:

```bash
opshaven verify-audit \
  --config "$HOME/.config/opshaven/config.json"
```

Treat a failed audit-chain verification as a security incident. Preserve the file and surrounding host evidence rather than rewriting it.