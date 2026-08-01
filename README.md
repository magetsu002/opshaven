# OpsHaven

**Let AI troubleshoot your Linux VPS without giving it a shell.**

OpsHaven is a professional operator CLI and MCP server for approved Linux inspection and controlled operations over restricted SSH. Operators use normal terminal commands; generated configuration, keys, authorization data, receipts, plans, and runtime verification stay behind the CLI.

## Operator workflow

A normal installation follows these commands:

```bash
opshaven init
opshaven setup remote
opshaven doctor
opshaven boundary verify
```

The supported V1.1 deployment workflow is:

```bash
opshaven app add
opshaven setup remote
opshaven deploy plan sample-api --revision <full-commit-sha>
opshaven deploy apply <plan-id>
opshaven doctor
```

Run `opshaven setup remote` after application registration so the newly generated deployment authorization is installed and verified at the restricted remote boundary. You do not need to edit generated JSON, create authorization artifacts, inspect PEM files, create rollback metadata, or calculate internal runtime hashes.

## Install from a reviewed checkout

Requirements:

```text
Linux or macOS
Node.js 22 or newer
OpenSSH client tools
```

Install dependencies, validate the checkout, and create the `opshaven` command:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
npm run install:local
```

Confirm the installation:

```bash
opshaven --version
opshaven --help
```

`npm run install:local` builds the reviewed source and links its executable into your npm command path. The human command is `opshaven`; MCP clients launch `opshaven-mcp`.

## Initialize

Run the first-time wizard:

```bash
opshaven init
```

The wizard explains and validates:

- a friendly name for the remote machine;
- the SSH hostname or IP address and port;
- the administrator account used only during installation;
- the administrator SSH key;
- the pinned SSH host identity;
- final confirmation before protected local state is created.

When a host identity is already present in the selected `known_hosts` source, OpsHaven derives and displays its SHA-256 fingerprint. The operator must explicitly accept it. Cancellation or invalid input does not create incomplete setup state.

## Set up the remote machine

Run from the operator machine:

```bash
opshaven setup remote
```

The command shows the target, explains which work is local or remote, performs preflight checks, requests confirmation, installs the restricted runtime, configures authorization, verifies the security boundary, and prints the next commands.

Preview without changing the remote machine:

```bash
opshaven setup remote --dry-run
```

Reviewed non-interactive automation remains explicit:

```bash
opshaven setup remote --non-interactive --approve
```

## Register a deployment application

V1.1 supports one deliberately narrow deployment profile:

```text
existing Git repository on the approved host
complete Git commit SHA
fixed npm ci --ignore-scripts --no-audit --no-fund
fixed npm run build
versioned release directories
atomic current-release symlink switch
one approved systemd service restart
one bounded HTTP GET health check
automatic restoration of the previous active release
no database migrations
```

Register the application through the guided command:

```bash
opshaven app add
```

The wizard asks only for operator-facing facts: application name, configured remote target, repository path, release path, systemd unit, health endpoint, expected status, and rollback behavior. It rejects duplicate IDs, unsafe or overlapping paths, unsupported service units, unbounded commands, unsupported build strategies, and malformed health checks before changing protected state.

Application registration updates the protected local and remote policy sources atomically. If validation, persistence, or audit recording fails, the previous protected state is restored and no partial registration remains. Re-run remote setup afterward to install and certify the new authorization:

```bash
opshaven setup remote
```

A synthetic configuration might describe:

```text
Application: sample-api
Repository: /srv/opshaven-fixtures/sample-api/repository
Releases:   /srv/opshaven-fixtures/sample-api/releases
Service:    sample-api.service
Health:     http://127.0.0.1:3000/health
```

These names are examples only. OpsHaven does not discover applications or import configuration from unrelated repositories.

## Create an exact deployment plan

Planning is read-only:

```bash
opshaven deploy plan sample-api --revision <full-commit-sha>
```

The initial profile accepts exactly one complete 40-character Git commit SHA. It rejects branches, tags, `HEAD`, `latest`, abbreviated SHAs, and arbitrary ref expressions. The remote restricted runtime verifies that the commit resolves exactly and belongs to the configured repository source before a plan is stored.

Planning observes only the bounded state required for review:

- active release and exact current revision;
- approved service state;
- configured health result;
- available root-filesystem space;
- remote runtime availability;
- rollback release availability;
- exact target revision membership.

It does not fetch into active state, build, restart services, activate releases, run migrations, or change authorization.

Every typed operation declares its permitted resources, privilege, timeout, output bound, redaction policy, mutation class, verification, and rollback behavior. Plans never contain an arbitrary shell script or AI-provided command string.

### Plan identity

Each immutable stored plan receives an identity in this form:

```text
sha256:<digest>
```

The digest covers the complete canonical plan, including:

- schema and application identity;
- pinned target identity digest;
- observed-state fingerprint and observed deployment state;
- current and target revisions;
- ordered typed operations and their limits;
- authorization mechanism, operator profile, and exact scope;
- required privileges and health checks;
- rollback release, revision, and operations;
- risk classification;
- policy, application-binding, and operation-definition digests;
- creation time, expiration time, and nonce.

For unchanged application configuration, requested revision, observed state, policy, target identity, operator authorization, and operation definitions, repeated planning returns the same still-valid stored plan. Once a relevant input changes or the plan expires, a new plan is required and receives a different digest.

Normal output separates observed state, proposed operations, verification, rollback, risk, expiration, plan ID, and the exact next command. `--json` returns the same information as structured data. `NO_COLOR` and non-TTY output remain supported.

## Apply only the stored plan

Apply accepts only an existing immutable plan ID:

```bash
opshaven deploy apply <plan-id>
```

Interactive apply shows the exact release mutation, approved service restart, and prepared rollback, then defaults to cancellation. A confirmed interactive apply internally creates the repository's existing one-time cryptographic approval for the exact resolved deployment operation.

Non-interactive apply requires an existing signed one-time approval token bound to the exact application, current state, target revision, policy version, expiration, and operator scope. There is no `--yes` bypass and no apply-time override for application, revision, health check, operations, or rollback strategy.

Immediately before mutation, OpsHaven revalidates:

- stored plan digest and expiration;
- application binding and target host identity;
- operator authorization and policy version;
- operation definitions;
- current deployed revision and observed-state fingerprint;
- rollback release availability;
- disk, runtime, service, and health state;
- exact target revision membership.

A stale or changed plan fails closed. OpsHaven does not refresh it automatically:

```text
Deployment plan is stale.
Cause
The remote deployment state or authorization changed after planning.
Changes
No changes were made.
Next
Create a new deployment plan.
```

Persistent owner-only execution markers prevent plan replay. A filesystem lock prevents conflicting apply operations for the same application. A rollback failure retains that lock as explicit recovery state instead of allowing another deployment to guess the remote state.

## Activation, verification, and rollback

The deployment engine never builds inside the active release. It verifies the exact source commit, creates a new detached versioned worktree, runs only the fixed bounded build steps, confirms the prepared directory is safe, records the previous active release, atomically switches the active symlink, and restarts only the approved systemd unit.

A deployment succeeds only when all configured checks pass:

- approved service is active;
- HTTP health check returns the expected status within its timeout and response bound;
- the active release is the expected versioned release;
- the exact target revision is active.

If post-activation verification fails, the constrained remote engine restores the recorded previous release, restarts the same approved service, reruns health verification, and confirms the previous exact revision. OpsHaven reports one of four distinct outcomes:

```text
DEPLOYMENT_SUCCEEDED
DEPLOYMENT_FAILED_ROLLED_BACK
DEPLOYMENT_FAILED_ROLLBACK_FAILED
DEPLOYMENT_NOT_STARTED
```

A successful rollback does not turn a failed deployment into success. A rollback failure is reported prominently and leaves persistent recovery state for operator inspection.

## Audit and recovery

Application registration, plan creation or rejection, approval, apply start, typed operation results, verification, deployment completion or failure, rollback start, and rollback result are appended to the existing tamper-evident audit chain.

Deployment audit evidence contains digests and bounded structured fields. It does not record private keys, tokens, environment values, credentials, or raw build output. Audit verification failure before mutation blocks apply. If critical evidence recording fails after mutation, OpsHaven attempts the exact rollback path rather than reporting success.

Use:

```bash
opshaven doctor
opshaven verify-audit
```

The doctor report includes deployment application validity, remote release readiness, approved service availability, health reachability, rollback availability, the current blocker, and the next plan command. Normal output hides protected filenames; use `--debug` only for lower-level diagnostics.

## Unsupported deployment types

V1.1 does not support:

- database migrations or secret rotation;
- arbitrary hooks or arbitrary shell commands;
- containers, Docker Compose, Kubernetes, or cloud provisioning through the guided profile;
- multi-host, fleet, or multi-service coordinated releases;
- automatic application discovery;
- branch, tag, or moving-ref deployment;
- AI-generated deployment operations;
- web-dashboard deployment controls.

A deployment requiring one of these features must not be forced through the supported profile.

## Diagnose

Use `doctor` as the main troubleshooting command:

```bash
opshaven doctor
```

The normal report separates:

```text
Local environment
Remote connection
Authorization state
Security verification
Deployment
Next action
```

It does not print internal filenames or private material. Add `--debug` only when lower-level support details are required:

```bash
opshaven doctor --debug
```

## Verify

After setup succeeds:

```bash
opshaven boundary verify
```

This verifies the installed restrictions, authenticated execution, read-only enforcement, replay resistance, response verification, and audit integrity. A failure returns a nonzero exit code.

Review the current operator authorization summary with:

```bash
opshaven authorization-report --mode read-only
```

## Operate

Use an MCP client with the generated configuration:

```bash
opshaven print-mcp-config
```

The MCP client launches:

```text
opshaven-mcp --config <generated configuration>
```

The `opshaven-mcp` process speaks MCP JSON-RPC over stdio. It is not an interactive terminal interface.

Controlled local operations still require exact one-time approvals:

```bash
opshaven approve-restart --resource service.example
opshaven approve-deploy --resource deployment.example --commit <sha>
opshaven approve-rollback --resource deployment.example --release <release-id>
```

Rollback and uninstall use the protected setup record:

```bash
opshaven setup remote --rollback --approve
opshaven uninstall remote --approve
```

## Terminal behavior

OpsHaven uses consistent symbols and optional terminal colors:

- green for success;
- yellow for warnings, pending work, and confirmation;
- red for failures and blockers;
- blue for information and next commands.

Colors are presentation only. Disable them with either:

```bash
NO_COLOR=1 opshaven doctor
OPSHAVEN_COLOR=never opshaven doctor
```

Machine-readable commands continue to support `--json` where documented.

## What OpsHaven enforces

- restricted SSH with pinned host verification;
- logical resource IDs instead of arbitrary commands or paths;
- exact authorization and request validation;
- bounded, redacted output;
- replay-resistant authenticated requests and responses;
- read-only remote profiles;
- one-time approvals for controlled local changes;
- immutable exact-revision deployment plans;
- health-gated activation and automatic previous-release restoration;
- tamper-evident audit history;
- independent installed-boundary verification.

OpsHaven does not claim absolute security or universal deployment safety. Its boundary still depends on the VPS kernel, filesystem and ownership enforcement, OpenSSH, Git, Node.js, npm, systemd, configured resource mappings, health endpoint correctness, identity provider, proxy or tunnel, operator-owned keys, and the reviewed application build behaving as configured.

## Development

Install dependencies and run the human CLI directly from source:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run dev:cli -- --help
npm run dev:cli -- doctor
```

Run the complete validation suite:

```bash
npm test
npm run release:check
npm run security
npm run reproducible:check
```

Deployment tests use only synthetic local fixtures and disposable state owned by this repository. They do not connect to a real VPS or external application repository.

Start the MCP protocol process only when testing an MCP client:

```bash
npm run start:mcp -- --config /absolute/path/to/generated-config.json
```

## Documentation

Read the [operator workflow](docs/operator-workflow.md) for the normal command sequence and the [setup guide](docs/setup.md) for host identity preparation, automation, rollback, and troubleshooting.

See the [security guide](docs/security.md) for the enforced boundary and the [architecture guide](docs/architecture.md) for implementation details. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). OpsHaven is provided under the [MIT License](LICENSE).
