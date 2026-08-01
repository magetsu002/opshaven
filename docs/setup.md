# Setup

This guide connects OpsHaven to a restricted Linux target. Begin with a disposable machine containing no production secrets or customer data.

## Requirements

The operator machine needs Linux or macOS, Node.js 22 or newer, OpenSSH client tools, a clean reviewed checkout, an administrator SSH identity, and an independently verified SHA-256 SSH host identity.

The remote machine needs a supported Ubuntu or Debian release, Python 3, OpenSSH, OpenSSL, `setpriv`, Node.js 22 or newer at a reviewed absolute path, and sufficient free space.

## Install the operator CLI

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
npm run install:local
```

Confirm:

```bash
opshaven --version
opshaven --help
```

## Pin the SSH host identity

OpsHaven never silently trusts the first server key it sees. Collect the key and compare its fingerprint through an independent trusted channel:

```bash
ssh-keyscan -t ed25519 your-host.example \
  > "$HOME/.ssh/opshaven-known-hosts.pending"

ssh-keygen -lf \
  "$HOME/.ssh/opshaven-known-hosts.pending" \
  -E sha256
```

After independent verification:

```bash
mv "$HOME/.ssh/opshaven-known-hosts.pending" \
  "$HOME/.ssh/opshaven-known-hosts"
chmod 644 "$HOME/.ssh/opshaven-known-hosts"
```

A live scan collects a key; independent comparison establishes the expected identity.

## Initialize locally

Run:

```bash
opshaven init
```

The wizard validates the target label, SSH address, administrator account used only for installation, administrator private key, pinned `known_hosts` source, detected fingerprint, and final confirmation.

Nothing is installed remotely. Invalid input or cancellation leaves no partial setup state.

Reviewed non-interactive initialization remains explicit:

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

After initialization, register the application before remote setup:

```bash
opshaven app add
```

This allows the initial remote installation to include the runtime and reviewed deployment authorization together.

## Register the deployment application

The guided command asks for:

```text
application ID and friendly name
configured remote target
absolute remote Git repository path
absolute versioned-release path
approved systemd service unit
credential-free HTTP health URL
expected health status
fixed rollback behavior
```

It rejects duplicate IDs, unsafe or overlapping paths, malformed services or URLs, unsupported build strategies, moving references, arbitrary commands, and migrations before changing protected local state.

Registration is local and atomic. It does not upload, restart, or activate anything.

## Preview remote setup

```bash
opshaven setup remote --dry-run
```

The preview compares canonical local and installed identities and reports one classification:

```text
NO_CHANGE
AUTHORIZATION_ONLY
APPLICATION_DECLARATION_ONLY
AUTHORIZATION_AND_DECLARATION
RUNTIME_UPDATE
DISPATCHER_UPDATE
FULL_INSTALL
REPAIR_REQUIRED
```

## Install or synchronize

```bash
opshaven setup remote
```

Reviewed automation:

```bash
opshaven setup remote --non-interactive --approve
```

The first full installation normally takes one to three minutes. Later synchronization runs are normally faster. Do not close the terminal while a step is active.

The setup engine:

1. validates the reviewed source and protected local files;
2. verifies the pinned host identity, SSH access, platform, architecture, Node.js compatibility, disk, and privilege;
3. inspects the complete installed identity;
4. selects the smallest safe state transition;
5. stages changed artifacts into a new recorded generation;
6. activates the runtime, dispatcher, authorization, and declaration set atomically;
7. verifies authenticated requests and responses, replay denial, unknown-operation denial, unknown-resource denial, audit integrity, and the security boundary;
8. evaluates the same canonical readiness model used by doctor, boundary verification, and deployment;
9. reports success only when the exact installed state is deployment-ready.

OpsHaven uses one capability-scoped controlled dispatcher. Host-only authorization remains read-only because its signed operation and resource scope excludes deployment mutation.

## Canonical installed state

The canonical comparison covers:

```text
setup schema version
installation generation
runtime source version
runtime artifact digest
dispatcher mode
dispatcher digest
policy version and digest
signed capability identity
reviewed declaration digest
registered application scope
operator verification identity
remote platform and architecture
Node.js version compatibility
```

The model is derived from complete verified artifacts. A receipt, filename, timestamp, or one existing file is never sufficient proof.

## Fast paths

### No change

When all identities match:

```text
✓ Runtime already current
✓ Dispatcher already compatible
✓ Authorization already current
✓ Application scope already current
✓ Security boundary verified

No remote changes were required.
```

No runtime upload, dependency installation, dispatcher replacement, signed-state rewrite, unrelated restart, or generation change occurs. Verification still runs.

### Authorization only

When signed policy, capability, operator identity, or application scope changes:

```text
Updating remote authorization

✓ Existing runtime verified
✓ Existing dispatcher compatible
✓ Signed authorization updated
✓ Capability digest confirmed
✓ Security boundary verified
```

The runtime is not reinstalled.

### Declaration only

When only reviewed declaration state changes:

```text
Updating deployment application scope

✓ Existing runtime verified
✓ Existing dispatcher compatible
✓ Application declaration updated
✓ Authorized resources confirmed
✓ Security boundary verified
```

### Runtime or dispatcher update

Only changed verified artifacts are uploaded. The previous generation is retained until post-update certification succeeds.

### Repair required

Partial, unsafe, unsupported, or unclassifiable identity returns `REPAIR_REQUIRED`. No automatic mutation occurs.

## Setup outcomes

JSON receipts distinguish:

```text
SETUP_SUCCEEDED
SETUP_NO_CHANGE
SETUP_FAILED_NO_MUTATION
SETUP_FAILED_ROLLED_BACK
SETUP_FAILED_ROLLBACK_FAILED
SETUP_CANCELLED_NO_MUTATION
SETUP_CANCELLED_ROLLED_BACK
```

A failed update followed by a successful rollback remains a failed update. A rollback failure is never hidden.

## Safe cancellation

Cancellation is checked before mutation, after staging, before activation, after activation, during verification, and before success.

When cancellation arrives after mutation begins, OpsHaven restores the previous recorded runtime, dispatcher, policy, authorization, declarations, and canonical state, verifies the restored checkpoint, records the outcome, and reports whether rerun is safe.

## Diagnose

```bash
opshaven doctor
```

Normal mode reports operator-facing readiness and one next action.

For sanitized expected-versus-installed evidence:

```bash
opshaven doctor --debug
```

Debug comparison includes runtime, dispatcher, policy, capability, declaration, application scope, platform, architecture, Node.js version, generation, diagnosis, and repair. It excludes private keys, approval tokens, raw signed payloads, secrets, and unredacted environment values.

JSON remains stable and contains no ANSI escape sequences:

```bash
opshaven doctor --debug --json
```

## Verify the installed boundary

```bash
opshaven boundary verify
```

Boundary verification uses the same canonical readiness evaluator as doctor. It fails when runtime, dispatcher, authorization, declaration, or registered application scope is incompatible.

It also verifies shell denial, arbitrary-command denial, sudo denial, unauthorized-write denial, Docker socket denial, PTY and forwarding restrictions, unknown operation and resource denial, replay and mutation resistance, response authentication, host-key pinning, malformed-input structure, bounded output, secret scanning, and audit integrity.

## Plan a deployment

Interactive planning:

```bash
opshaven deploy plan sample-api
```

Non-interactive planning requires the complete immutable SHA:

```bash
opshaven deploy plan sample-api \
  --revision 0123456789abcdef0123456789abcdef01234567 \
  --non-interactive
```

Deployment planning and apply are blocked unless canonical remote readiness is compatible.

## Roll back or uninstall setup

Restore the previous recorded generation:

```bash
opshaven setup remote --rollback --approve
```

Remove only fixed OpsHaven paths and the exact restricted SSH entry:

```bash
opshaven uninstall remote --approve
```

Unrelated SSH keys, users, services, files, and SSH configuration are preserved.

## Color and automation

Color is optional:

```bash
NO_COLOR=1 opshaven doctor
OPSHAVEN_COLOR=never opshaven setup remote
```

Use `--json` where supported.

## Endpoint handoff

Endpoint exposure remains a separate reviewed action. Follow [Secure remote MCP](remote-mcp.md) after the restricted setup and boundary are healthy.
