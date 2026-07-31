# Setup

This guide connects OpsHaven to a restricted Linux VPS. Start with a disposable server that contains no production secrets or customer data. The automated workflow installs only the isolated read-only dispatcher.

## Requirements

The operator machine needs:

- Linux or macOS;
- Node.js 22 or newer;
- a clean checkout at the exact reviewed commit;
- OpenSSH client tools at their standard absolute paths;
- an administrator SSH identity;
- a separately verified SHA-256 SSH host-key fingerprint.

The VPS needs a supported Ubuntu or Debian release, Python 3, OpenSSH, OpenSSL, `setpriv`, at least 128 MiB of free space, and Node.js 22 or newer at a reviewed absolute path.

Validate and build the reviewed checkout:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
npm run build
```

## Verify the VPS host key

Collect the server key into a temporary file:

```bash
ssh-keyscan -t ed25519 your-host.example \
  > "$HOME/.ssh/opshaven-known-hosts.pending"
```

Display its SHA-256 fingerprint:

```bash
ssh-keygen -lf \
  "$HOME/.ssh/opshaven-known-hosts.pending" \
  -E sha256
```

Compare the fingerprint through a separate trusted channel. Only after it matches, move the file into the location you will give to `opshaven init`:

```bash
mv "$HOME/.ssh/opshaven-known-hosts.pending" \
  "$HOME/.ssh/opshaven-known-hosts"
chmod 644 "$HOME/.ssh/opshaven-known-hosts"
```

OpsHaven does not silently use trust on first use.

## Initialize the operator environment

Run:

```bash
opshaven init
```

In an interactive terminal, the command asks for the remote host, SSH port, administrator user, administrator SSH identity, pinned known-hosts file, and verified host-key fingerprint.

OpsHaven then creates, with protected permissions:

- the local operator state directory;
- authorization signing keys;
- approval state and replay secret;
- a restricted-account SSH key;
- local and remote policy configuration;
- setup state for installation, rollback, and uninstall.

Normal output does not display internal filenames, private key contents, or secret values.

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

Use `--privilege root` only when the administrator SSH user is root. Use `sudo-noninteractive` for a reviewed administrator account with non-interactive sudo access required by installation.

`opshaven init` is idempotent. It does not rotate existing local keys during a normal repeat run.

## Preview and install

Preview every local and VPS mutation without applying it:

```bash
opshaven setup remote --dry-run
```

Run the guided terminal workflow:

```bash
opshaven setup remote --tui
```

For CI or another reviewed non-interactive environment, approval remains explicit:

```bash
opshaven setup remote --non-interactive --approve
```

The CLI automatically locates the setup state created by `opshaven init`.

The engine still performs the same security checks:

1. verifies the exact local source head, local files, key correspondence, pinned host fingerprint, SSH connectivity, remote platform, resolved Node executable, disk space, privilege, and existing installation state;
2. creates or validates the locked `opshaven` account with no sudo or privileged-group membership;
3. installs the complete hashed read-only runtime tree, forced-command wrapper, policy, and restricted `authorized_keys` entry atomically;
4. generates and verifies signed read-only authorization locally;
5. uploads only public verification material and signed policy data;
6. generates the response-signing private key on the VPS and downloads only its public key;
7. proves shell denial, command denial, host-key pinning, signed authorization, authenticated read-only execution, replay and mutation resistance, malformed-input denial, and audit integrity;
8. writes matching local and remote receipts only after certification succeeds.

A repeat run is idempotent. Unchanged runtime and installation files are retained rather than replaced.

## Diagnose current state

Run:

```bash
opshaven doctor
```

The normal output reports:

- the current workflow state;
- completed setup steps;
- the current blocker;
- the exact next command.

Examples:

```text
Current state:
LOCAL_INITIALIZED

Blocked:
✗ Remote deployment not configured

Next action:
opshaven setup remote
```

```text
Current state:
READY

Blocked:
None

Next action:
No action required.
```

Use debug output only for troubleshooting:

```bash
opshaven doctor --debug
```

Debug mode includes lower-level validation results while still sanitizing protected paths and never printing private keys or secret values.

## Verify the installed boundary

Run:

```bash
opshaven boundary verify
```

The CLI automatically locates the generated local policy and setup state. A failed assertion returns nonzero. Endpoint handoff remains blocked until the protected remote receipt contains a matching successful certification.

Review active authorization separately:

```bash
opshaven authorization-report --mode read-only
```

## Roll back or uninstall

Rollback restores only files recorded in the protected setup receipt and removes newly created recorded files:

```bash
opshaven setup remote --rollback --approve
```

Uninstall removes only fixed OpsHaven paths and the exact forced-command key entry. It preserves unrelated `authorized_keys` entries, unrelated files, users, services, and SSH configuration:

```bash
opshaven uninstall remote --approve
```

Both commands emit a machine-readable receipt. Omit `--approve` to confirm that destructive execution remains blocked.

## Existing installations

Explicit configuration remains supported for compatibility and debugging:

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

Existing policy files, signed authorization artifacts, receipts, and remote installations do not need to be renamed or regenerated solely to use the guided CLI.

## Error translation and debugging

Normal setup failures use operator actions rather than internal schema or cryptographic names:

```text
Setup state is missing or outdated.

Run:
opshaven init
```

```text
Authorization setup is incomplete.

Run:
opshaven init
```

Add `--debug` to the failing command to see the original validation message:

```bash
opshaven setup remote --dry-run --debug
```

Debug mode is intended for troubleshooting and support. It does not disable validation, signature checks, rollback protection, boundary verification, least privilege, or audit behavior.

## Prepare endpoint handoff

Create a reviewed remote MCP companion configuration as described in [Secure remote MCP](remote-mcp.md). The endpoint configuration remains explicit because it contains deployment-specific OIDC, Host, Origin, proxy, rate-limit, and request-bound policy.

Prepare generic HTTPS proxy or tunnel instructions:

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

The command refuses public OpsHaven binding, credential-bearing URLs, mismatched paths, permissive proxy state, missing OIDC assumptions, wildcard CORS evidence, and endpoints that accept anonymous MCP requests.

## Troubleshooting

### Setup is not initialized

Run:

```bash
opshaven init
```

For a non-interactive environment, provide the remote host, administrator identity, known-hosts file, verified fingerprint, and privilege flags shown above.

### The source identity cannot be detected

Run OpsHaven from the clean reviewed Git checkout. Reviewed automation may pass the exact commit explicitly:

```bash
opshaven init --source-sha <40-character-reviewed-commit> ...
```

### Missing remote Node.js candidate

Install Node.js 22 or newer on the VPS at `/usr/local/bin/node` or `/usr/bin/node`, then rerun:

```bash
opshaven setup remote
```

### Advanced validation failure

Run the same command with `--debug`, correct the reported prerequisite without weakening the boundary, and rerun the normal command.
