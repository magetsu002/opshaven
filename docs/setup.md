# Setup

This guide connects a local OpsHaven MCP server to a restricted Linux VPS.

Start with a disposable server that contains no production secrets or customer data. The safest first installation uses the isolated read-only dispatcher.

## Requirements

You need Node.js 22 or newer, SSH access to the VPS, and a dedicated non-root VPS account.

Clone the repository, install dependencies, and verify the project:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
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

Generate all operator keys locally. Keep private keys on the operator-controlled machine and copy only the public material required by the dispatcher to the VPS.

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

## Choose a dispatcher mode

### Read-only mode

Use the isolated read-only dispatcher for first-time evaluation and routine diagnosis. It contains no restart, deployment, rollback, approval-consumption, sudo, or Docker control handlers.

A read-only installation should also have:

- no sudo rules;
- no write access to application or deployment paths;
- no system Docker socket access;
- no approval private key on the VPS;
- a root-owned dispatcher, policy, capability manifest, and trust files.

Install `packaging/opshaven-readonly-force-command` as the forced command and use the read-only build produced by the repository. Review [Remote confinement](remote-confinement.md) before adapting the reference systemd profile.

### Controlled mode

Controlled mode supports narrowly approved restart, deployment, and rollback operations. Enable it only after reviewing the required filesystem writes, health-probe networking, rootless container access, and exact sudo rules.

Do not permit wildcards, shells, editors, package managers, arbitrary environment assignment, unrestricted `systemctl`, or membership in a root-equivalent Docker group.

Start from [the sudoers example](sudoers.example) and create one reviewed rule per allowed systemd unit.

## Install the restricted dispatcher

Build OpsHaven and copy the selected compiled dispatcher, validated remote configuration, restricted SSH public key, signed capability manifest, capability declaration and binding, operator public keys, and response-signing material to the VPS.

The dispatcher trust files must be root-owned, regular files with strict modes, and must not be symlinks. The signed capability manifest must match the installed dispatcher artifact and declared authority.

Use `scripts/bootstrap-remote.sh` for the controlled reference installation. For read-only mode, install the isolated dispatcher and read-only forced-command wrapper described above rather than granting controlled-mode privileges.

Test that an attempted custom SSH command returns a policy denial instead of a shell.

## Validate and connect

Run the local configuration checks:

```bash
opshaven validate-config \
  --config "$HOME/.config/opshaven/config.json"

opshaven diagnostics \
  --config "$HOME/.config/opshaven/config.json"
```

Then prove the installed boundary:

```bash
opshaven verify-boundary \
  --config "$HOME/.config/opshaven/config.json"
```

A failed assertion returns a nonzero exit code. Do not connect an AI client until every expected assertion passes.

Review the active capabilities and assumptions:

```bash
opshaven trust-report \
  --config "$HOME/.config/opshaven/config.json"
```

Use JSON output when integrating the report into another verification process.

Finally, generate the MCP client configuration:

```bash
opshaven print-mcp-config \
  --config "$HOME/.config/opshaven/config.json"
```

Add the generated entry to the MCP client configuration. OpsHaven must remain a local stdio process; do not expose it through HTTP or a public socket.

## Test safe operation

Begin with one or two read-only resources. Confirm that:

- only configured logical resources are visible;
- environment checks return presence information rather than values;
- logs are bounded and redacted;
- unknown operations and resources are rejected;
- arbitrary SSH commands do not run;
- responses authenticate against the expected request, capability, and dispatcher identity.

In controlled mode, test a mutation in dry-run mode and verify it reports `changed: false`.

A human should create an approval only after reviewing the exact target, expected state, operation digest, and expiry. Failed, expired, replayed, state-drifted, or modified approvals require a new review.

Deployments accept exact full commit IDs under configured refs and refuse dirty state or expected-current mismatches. Failed health verification restores the previous activation. Rollback accepts only releases recorded in the release ledger. Database migrations are not reversed automatically.

Verify the audit chain after testing:

```bash
opshaven verify-audit \
  --config "$HOME/.config/opshaven/config.json"
```

Treat a failed boundary check, trust-file check, authenticated response, or audit-chain verification as a security incident. Preserve the surrounding evidence rather than rewriting it.
