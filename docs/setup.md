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
DISPATCHER_ONLY
DISPATCHER_AND_AUTHORIZATION
RUNTIME_ONLY
RUNTIME_AND_DISPATCHER
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

The first full installation may take a few minutes. Dispatcher-only and authorization-only synchronization should normally be faster. Do not close the terminal while a step is active.

The setup engine:

1. inspects the complete installed state and any prior synchronization transaction;
2. validates the reviewed source and protected local files;
3. verifies pinned host identity, SSH access, platform, architecture, Node.js, disk, and privilege;
4. selects the smallest safe state transition;
5. stages changed artifacts and verifies their exact identities;
6. records an immutable previous-generation snapshot and receipt chain;
7. refuses activation when rollback material is incomplete;
8. activates only the classified runtime, dispatcher, authorization, and declaration changes;
9. verifies authenticated requests and responses, replay denial, unknown-operation denial, unknown-resource denial, audit integrity, and the security boundary;
10. evaluates the same canonical readiness model used by doctor, boundary verification, and deployment;
11. commits the new generation only after every verification passes.

OpsHaven uses one capability-scoped controlled dispatcher. Host-only authorization remains read-only because its signed operation and resource scope excludes deployment mutation.

## Canonical installed and receipt identity

The canonical comparison covers:

```text
setup schema version
installation generation
runtime-core artifact digest
dispatcher mode and artifact digest
policy version and digest
signed capability identity
reviewed declaration digest
registered application scope
operator verification identity
remote platform and architecture
Node.js version compatibility
recorded generation integrity
```

The canonical generation receipt binds:

```text
receipt schema version
installation generation
runtime-core digest
dispatcher digest
policy digest
authorization digest
declaration digest
platform and architecture
source build identity
creation metadata
previous generation identity
```

Artifact identity is distinct from the temporary staging path, upload location, installation destination, and historical snapshot location. A valid artifact can move through fixed temporary paths without changing identity. Modified content, modified receipt fields, wrong generation, wrong dispatcher or policy, wrong host binding, and wrong previous-generation binding are rejected.

## Synchronization transaction

Mutating setup uses these phases:

```text
INSPECT
PLAN
STAGE
VERIFY_STAGED
RECORD_PREVIOUS
ACTIVATE
VERIFY_ACTIVE
COMMIT
CLEANUP
```

Rollback uses:

```text
ROLLBACK_START
RESTORE_PREVIOUS
VERIFY_RESTORED
ROLLBACK_COMMIT
ROLLBACK_CLEANUP
```

The previous verified generation remains available until the new generation passes runtime, dispatcher, authorization, declaration, application scope, authenticated protocol, boundary, doctor readiness, and audit checks.

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

### Authorization or declaration only

The installed runtime and dispatcher are reused. Only the changed signed authorization, reviewed declaration, or application scope is synchronized and verified.

### Dispatcher only

When runtime-core identity matches but the active dispatcher differs:

```text
Runtime
  unchanged

Dispatcher
  replacement required

Authorization
  update required when dispatcher binding changes
```

OpsHaven uploads one reviewed dispatcher artifact, performs no dependency installation, updates the runtime manifest and generation receipt, synchronizes matching authorization when required, then verifies compatibility, canonical readiness, and the boundary.

### Runtime change

The runtime is replaced only when exact runtime-core digest comparison proves it changed. Runtime-only and runtime-plus-dispatcher transitions remain distinct.

### Repair required

Partial, unsafe, unsupported, unclassifiable, or transaction-uncertain state returns `REPAIR_REQUIRED`. No automatic synchronization occurs.

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

A failed update followed by a successful rollback remains a failed update. Rollback success requires the restored generation to pass the same canonical and boundary verification. A rollback failure is never hidden or converted to success.

## Safe cancellation

Cancellation is checked before mutation, after staging, before activation, after activation, during verification, and before success.

When cancellation arrives after mutation begins, OpsHaven restores the exact recorded previous runtime, dispatcher, policy, authorization, declarations, and canonical state, verifies the restored checkpoint, records the outcome, and reports whether rerun is safe.

## Recovery after synchronization failure

Inspect sanitized recovery state:

```bash
opshaven doctor --debug
opshaven setup repair
```

The repair preview shows the transaction, last completed phase, desired and previous generation identities, rollback availability, and exact bounded changes.

Restore the last fully verified generation:

```bash
opshaven setup repair --approve
```

If no verified previous generation can be restored, preserve failed-state evidence and perform a reviewed clean reinstall:

```bash
opshaven setup repair --clean-reinstall --approve
```

The clean-reinstall path:

```text
copies every fixed managed active artifact into recovery evidence
copies the failed transaction and available transaction history
writes and verifies an evidence manifest
preserves audit history and forensic evidence
removes only fixed active OpsHaven paths
runs one normal full installation
verifies canonical readiness and the security boundary
```

It does not choose a generation by timestamp, trust a mutable receipt without verification, erase all state before inspection, or execute arbitrary shell repair.

## Progress output

Visible stages are built from the selected classification and begin at `[1/N]`. Hidden bookkeeping does not consume visible numbers and skipped stages do not create gaps.

TTY output clears and rewrites one complete line approximately every five seconds. It repaints immediately when the meaningful phase changes, respects terminal width, truncates by complete Unicode characters, and terminates the final line once.

Non-TTY output emits complete independent lines approximately every fifteen seconds and never uses carriage-return rewriting. JSON emits no progress animation or ANSI codes.

Dispatcher-only synchronization reports dispatcher upload, verification, activation, authorization synchronization, and boundary certification. It does not display dependency installation when dependencies are unchanged.

## Diagnose

```bash
opshaven doctor
```

Normal mode reports operator-facing readiness and one next action.

For sanitized expected-versus-installed and transaction evidence:

```bash
opshaven doctor --debug
```

Debug comparison includes:

```text
synchronization transaction status
last completed phase
desired, active, previous, and staged generation
runtime, dispatcher, policy, capability, and declaration digests
application scope
platform, architecture, and Node.js version
receipt integrity and host binding
rollback availability
canonical readiness
exact repair command
```

It excludes private keys, approval tokens, raw signed payloads, secrets, and unredacted environment values.

JSON remains stable and contains no ANSI escape sequences:

```bash
opshaven doctor --debug --json
```

## Verify the installed boundary

```bash
opshaven boundary verify
```

Boundary verification uses the same canonical readiness and transaction evaluator as doctor. It fails when the active generation is uncertain, the receipt chain is invalid, or runtime, dispatcher, authorization, declaration, or application scope is incompatible.

It still verifies shell denial, arbitrary-command denial, sudo denial, unauthorized-write denial, Docker socket denial, PTY and forwarding restrictions, unknown operation and resource denial, replay and mutation resistance, response authentication, host-key pinning, malformed-input structure, bounded output, secret scanning, and audit integrity.

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

Deployment planning and apply are blocked unless canonical remote readiness is compatible and the active synchronization generation is certain.

## Manual rollback or uninstall

The transaction-aware recovery command is preferred after synchronization failure:

```bash
opshaven setup repair
```

The legacy explicit setup rollback remains available for a complete recorded setup receipt:

```bash
opshaven setup remote --rollback --approve
```

Remove only fixed OpsHaven paths and the exact restricted SSH entry:

```bash
opshaven uninstall remote --approve
```

Unrelated SSH keys, users, services, files, SSH configuration, audit evidence, and preserved recovery evidence are not silently removed.

## Color and automation

Color is optional:

```bash
NO_COLOR=1 opshaven doctor
OPSHAVEN_COLOR=never opshaven setup remote
```

Use `--json` where supported.

## Endpoint handoff

Endpoint exposure remains a separate reviewed action. Follow [Secure remote MCP](remote-mcp.md) after the restricted setup and boundary are healthy.
