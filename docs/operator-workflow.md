# Operator workflow

OpsHaven keeps setup and verification details behind the human CLI. A Linux operator should not create internal configuration files, inspect private key files, or understand runtime implementation hashes to complete normal setup.

## Install

From a reviewed checkout:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
npm run install:local
```

Confirm the human command is available:

```bash
opshaven --version
opshaven --help
```

`opshaven` is the operator interface. `opshaven-mcp` is the stdio protocol process launched by an MCP client; it is not an interactive shell command.

For local development without installing the executable globally:

```bash
npm run dev:cli -- --help
npm run dev:cli -- doctor
```

## Initialize

Run:

```bash
opshaven init
```

The wizard begins by explaining that it runs on the operator machine and does not install anything remotely. It then asks for:

1. **Name** — a friendly label used in operator output.
2. **SSH address** — a hostname or IP address, optionally followed by `:port`.
3. **Administrator SSH user** — the account used only during installation.
4. **Administrator SSH private key** — an owner-only local key file.
5. **Pinned known_hosts file** — the local source that identifies the expected server.
6. **Host identity confirmation** — the detected or separately verified SHA-256 fingerprint.
7. **Final confirmation** — approval to create protected local operator state.

Example:

```text
OpsHaven first-time setup

Remote machine

Name [PRIMARY]: MAGETSU
SSH address: 13.63.19.157:22
Administrator SSH user [root]:

Host identity

Detected host identity:
SHA256:xxxxxxxx

Use this host identity? [y/N] y
✓ Host identity verified

Ready to initialize

Continue? [Y/n] y
```

Every prerequisite and confirmation is checked before persistence. Rejecting the host identity, cancelling final confirmation, or providing invalid input leaves no incomplete setup record.

For reviewed non-interactive automation:

```bash
opshaven init \
  --non-interactive \
  --host vps.example.test \
  --port 22 \
  --admin-user ubuntu \
  --admin-identity "$HOME/.ssh/vps-admin" \
  --known-hosts "$HOME/.ssh/known_hosts" \
  --host-key-sha256 "SHA256:verified-value" \
  --privilege sudo-noninteractive
```

Non-interactive setup never treats an automatically discovered fingerprint as operator approval. The expected fingerprint must be supplied after independent verification.

## Set up the remote machine

Run this command on the operator machine:

```bash
opshaven setup remote
```

The terminal identifies the target and walks through four operator-facing stages:

```text
OpsHaven Remote Setup

Runs from: operator machine
Remote setup target: vps.example.test:22

Checking

[1/4] ✓ Check installation prerequisites
[2/4] ✓ Install the restricted runtime
[3/4] ✓ Configure authorization
[4/4] ✓ Verify the security boundary
```

The command still performs all existing exact checks and mutations. The presentation layer does not skip, weaken, or replace security enforcement.

Preview without applying changes:

```bash
opshaven setup remote --dry-run
```

Use explicit approval in reviewed automation:

```bash
opshaven setup remote --non-interactive --approve
```

Add `--debug` to display lower-level setup evidence and the full reviewed mutation plan. Normal output intentionally hides internal paths and implementation hashes.

## Diagnose

Run:

```bash
opshaven doctor
```

`doctor` is the main troubleshooting command. Its normal output is organized around operator decisions:

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

The normal report does not reveal generated filenames, protected paths, private key material, or implementation-specific authorization terminology.

For support-level details:

```bash
opshaven doctor --debug
```

Debug output adds lower-level validation results while still sanitizing paths and never printing secret or private-key contents.

## Verify

After setup succeeds:

```bash
opshaven boundary verify
```

The CLI automatically locates generated operator and remote setup state. Boundary verification still proves shell denial, arbitrary-command denial, pinned host identity, authenticated authorization, replay resistance, response verification, read-only enforcement, and audit integrity.

## Operate

Print the MCP client configuration without locating internal files:

```bash
opshaven print-mcp-config
```

Review current authorization:

```bash
opshaven authorization-report --mode read-only
```

A normal completed sequence is:

```bash
opshaven init
opshaven setup remote
opshaven doctor
opshaven boundary verify
opshaven print-mcp-config
```

Rollback and uninstall use the protected setup record:

```bash
opshaven setup remote --rollback --approve
opshaven uninstall remote --approve
```

## Terminal and automation modes

OpsHaven uses colors and symbols only as presentation. Text, exit codes, checks, and JSON remain authoritative.

Disable color with:

```bash
NO_COLOR=1 opshaven doctor
OPSHAVEN_COLOR=never opshaven setup remote
```

Use `--json` for machine-readable output where supported. Use `--debug` for diagnostic detail. Neither option weakens validation.

## Security boundary

Private SSH and authorization material remains on the operator machine. Remote setup installs only the restricted runtime, public verification material, signed authorization data, replay state, and audit state required for independent enforcement.

The remote account has no interactive shell. The read-only installation has no sudo rule, deployment write access, system Docker socket access, or mutation handler. All existing authorization, signature, host verification, rollback, boundary verification, least privilege, and audit guarantees remain unchanged.
