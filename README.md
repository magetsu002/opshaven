# OpsHaven

**Let AI troubleshoot and deploy to a Linux VPS without giving it a shell.**

OpsHaven is an operator CLI and MCP server for approved Linux inspection and narrowly controlled operations over restricted SSH. Generated configuration, keys, signed authorization, receipts, plans, runtime identities, and rollback evidence remain behind the CLI.

## One-pass operator workflow

A fresh deployment-capable installation uses this order:

```bash
opshaven init
opshaven app add
opshaven setup remote
opshaven doctor
opshaven boundary verify
opshaven deploy plan sample-api
```

Only `opshaven setup remote` installs the remote runtime. Application registration happens first so the initial installation includes the reviewed application scope and deployment authorization.

After planning, apply only the stored immutable plan:

```bash
opshaven deploy apply <plan-id>
```

## Install from a reviewed checkout

Requirements:

```text
Linux or macOS operator machine
Node.js 22 or newer
OpenSSH client tools
supported Ubuntu or Debian remote machine
pinned and independently verified SSH host identity
```

Install and validate:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
npm run install:local
```

Confirm the human CLI:

```bash
opshaven --version
opshaven --help
```

`opshaven` is the operator interface. MCP clients launch `opshaven-mcp`; neither command grants an interactive remote shell.

## Initialize and register an application

Run:

```bash
opshaven init
opshaven app add
```

Initialization validates the operator environment, administrator SSH access used only for installation, pinned host identity, and owner-only local authorization material. Cancellation or invalid input does not leave partial setup state.

Application registration supports one deliberately narrow V1.1 profile:

```text
one existing Git repository on one approved host
one complete 40-character Git commit SHA
fixed npm ci --ignore-scripts --no-audit --no-fund
fixed npm run build
versioned release directories
atomic active-release switch
one approved systemd service restart
one bounded HTTP GET health check
automatic previous-release restoration
no database migrations
no arbitrary hooks or shell commands
```

Registration updates protected local policy and reviewed remote policy sources atomically. It does not install anything remotely.

## Set up or synchronize the remote target

Run:

```bash
opshaven setup remote
```

Preview the exact classification and mutation plan without changing the target:

```bash
opshaven setup remote --dry-run
```

Reviewed automation remains explicit:

```bash
opshaven setup remote --non-interactive --approve
```

OpsHaven uses one capability-scoped controlled dispatcher. A host-only capability remains read-only because its signed operation and resource scope contains no deployment mutation authority. Registering an application expands only the explicitly reviewed application resources and signed deployment operations.

The canonical installed-state model covers:

```text
setup schema version
installation generation
runtime source version and artifact digest
dispatcher mode and digest
policy version and digest
signed capability identity
reviewed declaration digest
registered application scope
operator verification identity
remote platform and architecture
Node.js compatibility
```

The same model is consumed by:

```text
setup remote
doctor
doctor --debug
boundary verify
deploy plan
deploy apply
```

A command cannot report deployment readiness by consulting a different dispatcher, capability, or policy artifact.

## Incremental setup classifications

Setup deterministically selects one state transition:

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

### No change

When every canonical identity matches, OpsHaven re-runs boundary and readiness verification without uploading runtime artifacts, reinstalling dependencies, rewriting authorization, or changing the installation generation.

### Authorization or declaration synchronization

When only signed policy, capability, application scope, or reviewed declaration state changes, OpsHaven reuses the installed runtime and compatible dispatcher. Only changed signed-state files and the next canonical generation are activated.

### Runtime or dispatcher update

Only changed reviewed artifacts are uploaded and activated. The previous verified generation remains recoverable until boundary and doctor-equivalent readiness checks pass.

### Repair required

Missing, unsafe, partial, or unsupported installed identity fails closed. OpsHaven does not infer validity from filenames, timestamps, or the presence of one artifact.

## Completion, rollback, and cancellation

Setup does not report success until all required postconditions pass, including pinned host identity, runtime and dispatcher identities, signed authorization, application scope, authenticated request and response verification, unknown-operation and unknown-resource denial, audit verification, boundary certification, and canonical doctor readiness.

Machine-readable setup outcomes are distinct:

```text
SETUP_SUCCEEDED
SETUP_NO_CHANGE
SETUP_FAILED_NO_MUTATION
SETUP_FAILED_ROLLED_BACK
SETUP_FAILED_ROLLBACK_FAILED
SETUP_CANCELLED_NO_MUTATION
SETUP_CANCELLED_ROLLED_BACK
```

If mutation has begun and setup fails or is cancelled, OpsHaven restores the recorded previous runtime, dispatcher, policy, authorization, declarations, and canonical state. A rollback failure remains visible and requires operator attention; it is never reported as success.

## Progress and performance evidence

Full installation explains that the first run normally takes one to three minutes. Quiet operations emit bounded elapsed-time updates. Authorization-only and no-change runs state that the installed runtime is being reused.

Integration receipts record phase timings for:

```text
local validation
remote inspection
artifact preparation
runtime installation
authorization synchronization
boundary verification
readiness verification
```

Disposable CI targets are:

```text
fresh full installation under 3 minutes
authorization-only synchronization under 20 seconds
no-change verification under 10 seconds
```

Verification is never skipped merely to meet a timing target.

## Diagnose and verify

Run:

```bash
opshaven doctor
opshaven boundary verify
opshaven verify-audit
```

Normal doctor output reports operator-facing readiness and the exact next command. Debug mode adds sanitized expected-versus-installed evidence:

```bash
opshaven doctor --debug
```

Debug output includes runtime, dispatcher, policy, capability, declaration, application scope, platform, architecture, Node.js version, generation, diagnosis, and repair command. It never prints private keys, tokens, raw signed payloads, or unredacted environment values.

Boundary certification includes the existing shell, command, forwarding, sudo, write, Docker socket, replay, request mutation, response mutation, host-key, malformed-input, output-bound, and audit checks. With registered applications it also requires canonical dispatcher, capability, declaration, and resource-scope compatibility. Boundary verification fails whenever canonical doctor readiness would fail.

## Exact deployment planning

Interactive planning discovers only verified immutable revisions from the configured repository:

```bash
opshaven deploy plan sample-api
```

Non-interactive and JSON callers must supply the complete revision:

```bash
opshaven deploy plan sample-api \
  --revision 0123456789abcdef0123456789abcdef01234567 \
  --non-interactive
```

Branches, tags, `HEAD`, `latest`, abbreviated SHAs, and arbitrary ref expressions are rejected. Planning is read-only and requires a healthy current release plus an available rollback release.

Each stored plan receives an immutable identity:

```text
sha256:<digest>
```

The digest covers the application, pinned target identity, observed state, exact current and target revisions, typed operations, authorization scope, privileges, health checks, rollback strategy, policy and operation-definition identities, expiration, and nonce.

Apply accepts only that stored plan ID. It revalidates canonical remote readiness and all plan-bound state immediately before mutation. Persistent markers prevent replay, and application locks prevent conflicting execution.

## Deployment activation and recovery

The constrained engine prepares a detached versioned release, runs only the fixed build operations, atomically switches the active release, and restarts only the approved service. Success requires the approved service, expected health status, expected release, and exact target revision.

Deployment outcomes remain distinct:

```text
DEPLOYMENT_SUCCEEDED
DEPLOYMENT_FAILED_ROLLED_BACK
DEPLOYMENT_FAILED_ROLLBACK_FAILED
DEPLOYMENT_NOT_STARTED
```

## Unsupported deployment types

V1.1 does not support database migrations, secret rotation, arbitrary hooks, arbitrary shell commands, containers, Kubernetes, cloud provisioning, coordinated fleets, moving Git references, automatic application discovery, or AI-generated deployment operations.

## Development and certification

Run:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run release:check
npm run security
npm run reproducible:check
```

Disposable integrations use only OpsHaven-owned synthetic fixtures. They do not connect to a real VPS or unrelated application repository.

## Documentation

Read the [operator workflow](docs/operator-workflow.md), [setup guide](docs/setup.md), [security guide](docs/security.md), and [architecture guide](docs/architecture.md). Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). OpsHaven is provided under the [MIT License](LICENSE).
