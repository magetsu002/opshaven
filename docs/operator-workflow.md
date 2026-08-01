# Operator workflow

OpsHaven keeps internal configuration, signed capabilities, declaration bindings, keys, receipts, hashes, and rollback metadata behind the human CLI.

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

After initialization:

```text
Next
  Register a deployment application:

  opshaven app add
```

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

Before the first remote setup, the next action is:

```text
✓ Application registered locally

The first remote setup will install the runtime and this reviewed deployment authorization together.

Next
  opshaven setup remote
```

For an older verified installation, OpsHaven compares exact content identities. It reuses the runtime whenever safe and updates only the dispatcher, signed authorization, declaration, or canonical state that changed.

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
RUNTIME_UPDATE
DISPATCHER_UPDATE
FULL_INSTALL
REPAIR_REQUIRED
```

### Full installation

The first run installs the capability-scoped controlled dispatcher, runtime, signed authorization, reviewed declarations, restricted SSH boundary, response-signing identity, and canonical state generation. It explains that the operation normally takes one to three minutes and emits bounded elapsed-time progress.

### No change

When all identities match, setup re-runs boundary and readiness verification without uploading runtime files, installing dependencies, rewriting signed state, or incrementing the generation.

### Authorization or declaration update

Only changed signed-state files are staged and activated. The existing verified runtime and dispatcher are reused.

### Runtime or dispatcher update

Only changed reviewed artifacts are uploaded. The previous verified generation remains available until post-update boundary and readiness certification succeeds.

### Repair required

Missing, partial, unsafe, unsupported, or unclassifiable identity fails closed. OpsHaven never guesses from timestamps or filenames.

Successful complete setup reports:

```text
✓ Remote setup complete
✓ Deployment capability synchronized
✓ Security boundary verified
✓ Sample API ready for planning

Next
  opshaven deploy plan sample-api
```

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

Cancellation is honored at safe checkpoints before mutation, after staging, before activation, after activation, during verification, and before success. If mutation has started, OpsHaven returns to the last recorded verified generation and reports the rollback result, active checkpoint, rerun safety, and exact next command.

## Diagnose

Run:

```bash
opshaven doctor
```

The normal report shows local readiness, remote connection, authorization, security verification, deployment readiness, and one next action.

Use sanitized detailed comparison output only when troubleshooting:

```bash
opshaven doctor --debug
```

Debug output compares expected and installed runtime version and digest, dispatcher mode and digest, policy, capability, declaration, application scope, platform, architecture, Node.js version, and installation generation. It never prints keys, tokens, raw signed payloads, or environment secrets.

## Verify the boundary

Run:

```bash
opshaven boundary verify
```

Boundary verification uses the same canonical installed-state model as doctor and deployment. It cannot pass while doctor reports deployment incompatibility.

The checks include shell and arbitrary-command denial, forwarding and PTY denial, sudo and unauthorized-write denial, Docker socket denial, unknown operation and resource denial, replay and mutation denial, response authentication, host-key pinning, malformed-input structure, bounded secret scanning, audit integrity, dispatcher identity, capability identity, declaration identity, and registered application scope.

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

Branches, tags, `HEAD`, `latest`, abbreviated SHAs, and arbitrary ref expressions are rejected. Planning is read-only and requires a healthy current release plus an available rollback release.

Each plan receives an immutable `sha256:<digest>` identity covering all security-relevant observed state, operations, authorization, health checks, rollback, policy, target identity, expiration, and nonce.

## Apply the exact plan

Run:

```bash
opshaven deploy apply <plan-id>
```

Apply accepts no application, revision, health, operation, or rollback overrides. It revalidates the canonical remote state and all plan-bound evidence immediately before mutation. Persistent markers prevent replay and locks prevent conflicting application deployment.

Deployment outcomes remain distinct:

```text
DEPLOYMENT_SUCCEEDED
DEPLOYMENT_FAILED_ROLLED_BACK
DEPLOYMENT_FAILED_ROLLBACK_FAILED
DEPLOYMENT_NOT_STARTED
```

## Audit and recovery

Run:

```bash
opshaven verify-audit
opshaven setup remote --rollback --approve
opshaven uninstall remote --approve
```

Rollback restores only recorded prior artifacts and removes only recorded newly created artifacts. Uninstall removes fixed OpsHaven paths and the exact restricted SSH entry while preserving unrelated server state.

## Terminal and automation behavior

Color is presentation only:

```bash
NO_COLOR=1 opshaven doctor
OPSHAVEN_COLOR=never opshaven setup remote
```

Non-TTY output remains readable. JSON contains no ANSI escape sequences.

## Unsupported deployment types

The V1.1 profile does not support database migrations, secret rotation, arbitrary shell commands, containers, Kubernetes, cloud provisioning, coordinated fleets, application auto-discovery, moving Git references, AI-generated operations, or dashboard deployment controls.
