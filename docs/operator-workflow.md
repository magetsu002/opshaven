# Operator workflow

OpsHaven keeps internal configuration, signed capabilities, declaration bindings, keys, receipts, transaction hashes, and rollback metadata behind the human CLI.

## Install

From a reviewed checkout:

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

`opshaven` is the human interface. MCP clients launch `opshaven-mcp`; neither provides an interactive remote shell.

## Clean-room sequence

Use this order for a new deployment-capable target:

```bash
opshaven init
opshaven app add
opshaven setup remote
opshaven doctor
opshaven boundary verify
opshaven deploy plan sample-api
```

Application registration occurs before remote setup so one full installation contains both the reviewed runtime and the initial deployment authorization.

## Initialize

Run:

```bash
opshaven init
```

Initialization validates the operator environment, administrator SSH identity, pinned host identity, and protected local authorization material. Nothing is installed remotely.

Rejecting the host identity, cancelling confirmation, or providing invalid input creates no incomplete setup state.

## Register an application

Run:

```bash
opshaven app add
```

The wizard asks for the application ID and label, configured target, remote Git repository, release directory, approved systemd service, health URL, expected status, and rollback behavior.

The supported profile is intentionally narrow:

```text
one approved host
one existing Git repository
complete immutable commit SHA
fixed npm install and build operations
versioned releases
atomic active-release switch
one approved systemd restart
one bounded HTTP health check
automatic previous-release restoration
no migrations or arbitrary hooks
```

Registration updates protected local and reviewed remote policy sources atomically. It does not install or restart anything.

## Install or synchronize

Run:

```bash
opshaven setup remote
```

Preview first when needed:

```bash
opshaven setup remote --dry-run
```

Non-interactive execution remains explicit:

```bash
opshaven setup remote --non-interactive --approve
```

Setup selects one deterministic classification:

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

### Full installation

The first run installs the capability-scoped controlled dispatcher, runtime, signed authorization, reviewed declarations, restricted SSH boundary, response-signing identity, and canonical generation. It explains that the operation may take a few minutes and emits bounded elapsed-time progress.

### No change

When all identities match, setup re-runs boundary and readiness verification without uploading runtime files, installing dependencies, rewriting signed state, or incrementing the generation.

### Authorization or declaration update

Only changed signed-state files are staged and activated. The existing verified runtime and dispatcher are reused.

### Dispatcher-only update

Runtime-core identity excludes the dispatcher artifact. When only the dispatcher or its authorization binding changes, OpsHaven reuses the runtime, uploads one reviewed dispatcher artifact, performs no dependency installation, synchronizes matching authorization when required, and verifies canonical readiness and the boundary.

### Runtime update

The runtime is replaced only when its exact core digest changed. Runtime-only and runtime-plus-dispatcher changes remain distinct.

### Repair required

Missing, partial, unsafe, unsupported, unclassifiable, or transaction-uncertain identity fails closed. OpsHaven never guesses from timestamps or filenames.

## Verified synchronization transaction

Before activation, OpsHaven records an immutable transaction and previous-generation snapshot. Normal phases are:

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

Rollback phases are:

```text
ROLLBACK_START
RESTORE_PREVIOUS
VERIFY_RESTORED
ROLLBACK_COMMIT
ROLLBACK_CLEANUP
```

The generation receipt binds runtime, dispatcher, policy, authorization, declaration, platform, architecture, source build, installation generation, and previous-generation identity. Temporary staging paths are not identities.

OpsHaven does not delete or overwrite previous-generation evidence until the new generation passes runtime, dispatcher, authorization, declaration, application-scope, authenticated protocol, audit, boundary, and doctor-equivalent readiness checks.

## Setup outcomes and cancellation

Machine-readable outcomes are explicit:

```text
SETUP_SUCCEEDED
SETUP_NO_CHANGE
SETUP_FAILED_NO_MUTATION
SETUP_FAILED_ROLLED_BACK
SETUP_FAILED_ROLLBACK_FAILED
SETUP_CANCELLED_NO_MUTATION
SETUP_CANCELLED_ROLLED_BACK
```

Cancellation is honored before mutation, after staging, before and after activation, during verification, and before success. If mutation has started, OpsHaven restores the exact recorded previous generation and verifies the restored boundary before reporting rollback success.

A rollback failure is possible and remains explicit. Normal output reports the failed phase, mutation status, rollback status, active-generation certainty, blocked operations, and safe next command without dumping stack traces.

## Recover a failed synchronization

Inspect the recovery state:

```bash
opshaven doctor --debug
opshaven setup repair
```

Restore the last fully verified generation:

```bash
opshaven setup repair --approve
```

When no verified prior generation is available, preserve evidence and perform a reviewed clean reinstall:

```bash
opshaven setup repair --clean-reinstall --approve
```

The clean-reinstall flow copies fixed managed artifacts and transaction history into recovery evidence, verifies its manifest, preserves audit history, removes only fixed active OpsHaven paths, performs one normal full installation, and verifies canonical readiness and the security boundary. It does not select state by mutable timestamps or erase evidence before inspection.

## Diagnose

Run:

```bash
opshaven doctor
```

Use sanitized detailed comparison output only when troubleshooting:

```bash
opshaven doctor --debug
```

Debug output shows:

```text
synchronization status and last completed phase
desired, active, previous, and staged generation
runtime, dispatcher, policy, capability, and declaration identities
application scope
platform, architecture, and Node.js version
receipt integrity and host binding
rollback availability
canonical readiness
exact repair command
```

It never prints keys, tokens, raw signed payloads, or environment secrets.

## Verify the boundary

Run:

```bash
opshaven boundary verify
```

Boundary verification uses the same canonical and transaction model as doctor and deployment. It cannot pass while the active generation is uncertain, the receipt chain is invalid, or doctor reports deployment incompatibility.

It still checks shell and arbitrary-command denial, forwarding and PTY denial, sudo and unauthorized-write denial, Docker socket denial, unknown operation and resource denial, replay and mutation denial, response authentication, host-key pinning, malformed-input structure, bounded secret scanning, audit integrity, dispatcher identity, capability identity, declaration identity, and registered application scope.

## Progress behavior

Visible progress is built from the selected classification and starts at `[1/N]`. Hidden planning does not consume visible numbers and skipped stages do not create gaps.

TTY output clears and repaints one complete width-bounded line approximately every five seconds. Non-TTY output writes complete independent lines approximately every fifteen seconds. JSON emits no animation or ANSI codes.

Progress messages come from the active transaction phase. Dispatcher-only setup never displays dependency installation.

## Choose and plan a revision

Interactive planning discovers verified immutable revisions:

```bash
opshaven deploy plan sample-api
```

Non-interactive and JSON callers must provide the full SHA:

```bash
opshaven deploy plan sample-api \
  --revision 0123456789abcdef0123456789abcdef01234567 \
  --non-interactive
```

Branches, tags, `HEAD`, `latest`, abbreviated SHAs, and arbitrary ref expressions are rejected. Planning is read-only and requires a healthy current release, an available rollback release, canonical remote readiness, and a resolved synchronization transaction.

Each plan receives an immutable `sha256:<digest>` identity covering all security-relevant observed state, operations, authorization, health checks, rollback, policy, target identity, expiration, and nonce.

## Apply the exact plan

Run:

```bash
opshaven deploy apply <plan-id>
```

Apply accepts no application, revision, health, operation, or rollback overrides. It revalidates canonical remote state, transaction certainty, and all plan-bound evidence immediately before mutation. Persistent markers prevent replay and locks prevent conflicting application deployment.

## Audit and uninstall

Run:

```bash
opshaven verify-audit
opshaven uninstall remote --approve
```

Uninstall removes fixed active OpsHaven paths and the exact restricted SSH entry while preserving unrelated server state and explicitly preserved recovery evidence.

## Terminal and automation behavior

Color is presentation only:

```bash
NO_COLOR=1 opshaven doctor
OPSHAVEN_COLOR=never opshaven setup remote
```

Non-TTY output remains readable. JSON contains no ANSI escape sequences.

## Unsupported deployment types

The V1.1 profile does not support database migrations, secret rotation, arbitrary shell commands, containers, Kubernetes, cloud provisioning, coordinated fleets, application auto-discovery, moving Git references, AI-generated operations, or dashboard deployment controls.
