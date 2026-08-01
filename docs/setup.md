# Setup

This guide connects OpsHaven to a restricted Linux VPS. Begin with a disposable server that contains no production secrets or customer data.

## Requirements

The operator machine needs:

- Linux or macOS;
- Node.js 22 or newer;
- a clean checkout at the exact reviewed commit;
- OpenSSH client tools at their standard absolute paths;
- an administrator SSH identity;
- a separately verified SHA-256 SSH host identity.

The VPS needs a supported Ubuntu or Debian release, Python 3, OpenSSH, OpenSSL, `setpriv`, at least 128 MiB of free space, and Node.js 22 or newer at a reviewed absolute path.

## Install the operator CLI

From the reviewed checkout:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
npm run install:local
```

Confirm the command is available:

```bash
opshaven --version
opshaven --help
```

For development without a linked installation:

```bash
npm run dev:cli -- --help
```

## Prepare a pinned host identity

OpsHaven never silently trusts the first server key it sees. Obtain the host key and verify its fingerprint through an independent trusted channel before accepting it.

One preparation method is:

```bash
ssh-keyscan -t ed25519 your-host.example \
  > "$HOME/.ssh/opshaven-known-hosts.pending"

ssh-keygen -lf \
  "$HOME/.ssh/opshaven-known-hosts.pending" \
  -E sha256
```

After the fingerprint is independently confirmed:

```bash
mv "$HOME/.ssh/opshaven-known-hosts.pending" \
  "$HOME/.ssh/opshaven-known-hosts"
chmod 644 "$HOME/.ssh/opshaven-known-hosts"
```

A live scan is only a collection mechanism. Independent fingerprint comparison is what establishes the expected host identity.

## Initialize the operator machine

Run:

```bash
opshaven init
```

The interactive wizard clearly separates a friendly machine name from the SSH network address. It explains each prompt, validates required files, detects a fingerprint from the pinned `known_hosts` source when possible, displays that fingerprint, and requires explicit acceptance.

Example:

```text
OpsHaven first-time setup

This wizard runs on your operator machine. Nothing is installed remotely until you run opshaven setup remote.

Remote machine

Name [PRIMARY]: MAGETSU
SSH address: 13.63.19.157:22
Administrator SSH user [root]:
Administrator SSH private key [/home/operator/.ssh/id_ed25519]:
Pinned known_hosts file [/home/operator/.ssh/known_hosts]:

Host identity

Detected host identity:
SHA256:xxxxxxxx

Use this host identity? [y/N] y
✓ Host identity verified

Ready to initialize

Continue? [Y/n] y
```

The final confirmation occurs before protected local state is created. Rejected confirmation, empty host identity, missing SSH files, or invalid input does not create incomplete state.

The wizard creates the local keys, generated configuration, authorization state, restricted SSH identity, and setup record required by later commands. Normal output does not display their filenames or secret contents.

For reviewed non-interactive automation:

```bash
opshaven init \
  --non-interactive \
  --host your-host.example \
  --port 22 \
  --admin-user ubuntu \
  --admin-identity "$HOME/.ssh/vps-admin" \
  --known-hosts "$HOME/.ssh/opshaven-known-hosts" \
  --host-key-sha256 "SHA256:separately-verified-value" \
  --privilege sudo-noninteractive
```

Use `--privilege root` only when the administrator SSH user is root. Use `sudo-noninteractive` for a reviewed administrator account with the narrowly required non-interactive installation permission.

## Preview remote setup

Preview the exact plan without applying changes:

```bash
opshaven setup remote --dry-run
```

The dry run remains detailed because its purpose is reviewing mutations. It does not connect through an unpinned SSH path or apply remote changes.

## Install the remote runtime

Run from the operator machine:

```bash
opshaven setup remote
```

The command displays:

- the selected remote target;
- that execution starts on the operator machine;
- the pinned host identity;
- preflight progress;
- installation progress;
- authorization progress;
- security verification progress;
- the exact next commands.

The operator must confirm before installation begins. For reviewed non-interactive automation, approval remains explicit:

```bash
opshaven setup remote --non-interactive --approve
```

The underlying engine still performs the same security work:

1. verifies the exact source checkout, safe local files, corresponding keys, pinned host identity, SSH access, remote platform, Node.js runtime, disk space, privilege, and existing installation state;
2. creates or validates the locked `opshaven` account without an interactive shell or privileged group membership;
3. installs the complete hashed read-only runtime and forced-command wrapper atomically;
4. prepares and verifies exact read-only authorization locally;
5. uploads only public verification material and signed authorization data;
6. generates response-signing material on the VPS and returns only public verification data;
7. verifies shell denial, arbitrary-command denial, host identity pinning, authenticated read-only execution, replay resistance, malformed-input denial, response verification, and audit integrity;
8. writes matching receipts only after successful certification.

A failure after installation begins invokes the existing rollback behavior. The presentation layer does not alter rollback scope or acceptance rules.

Use `--debug` to display the full mutation plan and lower-level verification identifiers:

```bash
opshaven setup remote --debug
```

## Diagnose current state

Run:

```bash
opshaven doctor
```

The report is organized as:

```text
OpsHaven Health

Local environment
Remote connection
Authorization state
Security verification
Next action
```

Typical incomplete setup:

```text
OpsHaven Health

Local environment
✓ Operator setup ready

Remote connection
✗ Remote setup not configured

Authorization state
! Waiting for remote verification

Security verification
○ Not yet verified

Next action
  opshaven setup remote
```

Use debug mode only for troubleshooting:

```bash
opshaven doctor --debug
```

Debug mode adds lower-level validation results while continuing to sanitize protected paths and omit private keys and secret values.

## Verify the installed boundary

Run:

```bash
opshaven boundary verify
```

The CLI automatically locates generated operator and setup state. A failed assertion returns nonzero. Endpoint handoff remains blocked until the protected remote receipt contains matching successful verification.

Review the current authorization summary separately:

```bash
opshaven authorization-report --mode read-only
```

## Roll back or uninstall

Rollback restores only recorded prior files and removes only newly created recorded files:

```bash
opshaven setup remote --rollback --approve
```

Uninstall removes only fixed OpsHaven paths and the exact restricted key entry. It preserves unrelated SSH keys, files, users, services, and SSH configuration:

```bash
opshaven uninstall remote --approve
```

Omitting `--approve` confirms that destructive non-interactive execution remains blocked.

## Existing installations

Explicit paths remain supported for compatibility and support diagnostics:

```bash
opshaven setup remote \
  --dry-run \
  --config /absolute/path/to/existing-setup.json

opshaven doctor \
  --config /absolute/path/to/existing-local-config.json

opshaven boundary verify \
  --config /absolute/path/to/existing-local-config.json \
  --setup-config /absolute/path/to/existing-setup.json
```

Normal new-user setup does not require locating these files.

## Error handling

Normal failures answer three questions:

1. what happened;
2. which operator-facing check failed;
3. what to do or run next.

Example:

```text
✗ Remote setup cannot continue

Cause:
Administrator SSH authentication failed.

Checked:
✓ Host identity
✗ SSH authentication

Next:
Verify the administrator username and private key, then run the health check.

Run:
  opshaven doctor
```

Add `--debug` to the failing command to see the original lower-level validation message. Debug mode never disables authorization, signatures, host verification, rollback, boundary verification, least privilege, or audit behavior.

## Color and automation

Color is optional and never carries correctness information. Disable it with:

```bash
NO_COLOR=1 opshaven doctor
OPSHAVEN_COLOR=never opshaven setup remote
```

Use `--json` for machine-readable output where supported.

## Prepare endpoint handoff

Create a reviewed remote MCP companion configuration as described in [Secure remote MCP](remote-mcp.md). Endpoint configuration remains explicit because it contains deployment-specific identity, Host, Origin, proxy, rate-limit, and request-bound policy.

Prepare the handoff:

```bash
opshaven endpoint expose \
  --endpoint-config "$HOME/.config/opshaven/remote-endpoint.json" \
  --external-url "https://mcp.example.test/mcp"
```

After the external HTTPS route exists, prove that anonymous access remains denied:

```bash
opshaven endpoint expose \
  --endpoint-config "$HOME/.config/opshaven/remote-endpoint.json" \
  --external-url "https://mcp.example.test/mcp" \
  --verify-external
```

Inspect current handoff state:

```bash
opshaven endpoint status
```
