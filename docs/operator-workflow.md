# Operator workflow

OpsHaven keeps setup, deployment planning, authorization, and verification details behind the human CLI. A Linux operator should not create internal configuration files, inspect private key files, assemble capability artifacts, or calculate runtime hashes to complete normal work.

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

## Initialize

Run:

```bash
opshaven init
```

The wizard explains that it runs on the operator machine and does not install anything remotely. It asks for a friendly target name, SSH address, administrator account used only for installation, owner-only administrator key, pinned `known_hosts` source, independently verified host fingerprint, and final confirmation.

Every prerequisite and confirmation is checked before persistence. Rejecting the host identity, cancelling final confirmation, or providing invalid input leaves no incomplete setup record.

## Set up the remote machine

Run:

```bash
opshaven setup remote
```

The command identifies the target, performs exact preflight checks, installs the restricted runtime, configures authorization, verifies the boundary, and reports the next command.

Preview without changes:

```bash
opshaven setup remote --dry-run
```

Reviewed automation remains explicit:

```bash
opshaven setup remote --non-interactive --approve
```

Normal output hides protected paths and implementation hashes. Add `--debug` only when lower-level evidence is required.

## Register an application

Run:

```bash
opshaven app add
```

The guided workflow first explains the supported profile and then describes every field before asking for a value. Pressing Enter at every prompt accepts the complete bundled synthetic example.

The two application names have different purposes:

```text
Application ID
  Permanent lowercase identifier used in commands.
  Example: sample-api

Application name
  Friendly label shown in reports.
  Example: Sample API
```

The repository and release locations are absolute paths on the remote machine:

```text
Repository
  /srv/opshaven-fixtures/sample-api/repository

Releases
  /srv/opshaven-fixtures/sample-api/releases
```

The repository path identifies the reviewed Git repository containing the application code. The release path is where separate versioned releases are prepared. OpsHaven never builds incrementally inside the active release.

The initial profile remains narrow:

```text
Git repository on one approved remote machine
fixed npm install and build operations
versioned release directories
atomic active-release switch
one approved systemd service restart
one bounded HTTP GET health check
automatic previous-release restoration
```

Registration rejects unsafe or overlapping paths, duplicate IDs, malformed service identifiers, unsupported build strategies, credential-bearing health URLs, and arbitrary command input before persistence. Cancellation and validation failure create no partial state.

After registration, OpsHaven checks the real state before printing the next command:

- when the installed boundary already recognizes the application and a verified revision is available, it prints the plan command;
- when the updated application authorization still needs installation, it prints `opshaven setup remote`;
- when the repository or runtime is unavailable, it directs the operator to the relevant readiness check.

It does not print both actions indiscriminately.

## Understand application revisions

A revision is the exact ID of one saved version of the application code.

OpsHaven requires a complete Git commit SHA so approved code cannot later change because a branch or tag moved. A valid revision:

```text
contains exactly 40 hexadecimal characters
uses only 0-9 and a-f
belongs to the application's configured repository
```

A server fingerprint and an application revision are different:

```text
SHA256:...
  Identifies the remote server.

40-character Git commit SHA
  Identifies one exact saved application version.
```

Do not paste an SSH host fingerprint into `--revision`.

## Choose a revision interactively

For normal interactive use:

```bash
opshaven deploy plan sample-api
```

OpsHaven inspects only the configured repository through the existing bounded deployment boundary. It explains revisions, displays verified complete commit SHAs, and requires an explicit numbered selection.

For the bundled sample, the recommended healthy revision is derived from the actual synthetic repository. The full SHA is displayed at runtime rather than hardcoded in documentation. When a reviewed unhealthy rollback-test revision is available in the fixture, it is labeled separately and remains opt-in.

The selected value is always converted to and verified as a complete immutable 40-character SHA before plan creation. Branches, tags, `HEAD`, `latest`, abbreviated SHAs, and arbitrary ref expressions remain rejected.

## Plan non-interactively

Non-interactive and JSON callers must provide the exact revision explicitly:

```bash
opshaven deploy plan sample-api \
  --revision 0123456789abcdef0123456789abcdef01234567 \
  --non-interactive
```

The SHA above is a format example only. Use the complete SHA reported from the application's actual configured repository.

OpsHaven never silently chooses a revision for non-interactive or JSON planning.

Planning remains read-only. It may inspect:

```text
current active release and revision
approved service state
health state
available disk
runtime availability
rollback release
target revision membership
```

It does not build, restart, activate, run migrations, modify configuration, or change authorization.

## Review the immutable plan

Every plan receives an immutable identifier:

```text
sha256:<digest>
```

The digest covers the canonical security-relevant plan, including the application, target host identity, current and target revisions, observed-state fingerprint, typed operations, authorization scope, privilege requirements, health checks, rollback strategy, policy version, operation-definition digest, creation time, expiration, and nonce.

For unchanged inputs and still-valid stored state, the same deterministic plan can be reused. A changed application configuration, target identity, current revision, policy, health definition, rollback state, or expiration requires a new plan.

## Apply the exact plan

Run:

```bash
opshaven deploy apply <plan-id>
```

Interactive apply displays the exact release mutation, approved service restart, and prepared rollback, then defaults to No. Confirmation creates the existing one-time cryptographic authorization for that exact stored operation.

Non-interactive apply requires an existing signed approval token. There is no casual `--yes` bypass and no apply-time override for the application, revision, health check, operation list, or rollback strategy.

Immediately before mutation, OpsHaven revalidates:

```text
plan integrity and expiration
application and host identity
operator authorization and policy
operation definitions
current revision and observed state
rollback availability
disk and runtime
service identity and health
target commit membership
```

Any difference fails closed and requires a new plan.

## Activation and recovery

The constrained deployment engine verifies the exact source, creates a separate versioned release, runs only fixed bounded build operations, records the previous release, switches the active release atomically, and restarts only the approved systemd service.

Completion requires:

```text
approved service active
health status accepted
expected release selected
exact target revision active
```

If post-activation verification fails, OpsHaven restores the recorded previous release, restarts the approved service, reruns health verification, and confirms the previous revision.

Outcomes remain distinct:

```text
DEPLOYMENT_SUCCEEDED
DEPLOYMENT_FAILED_ROLLED_BACK
DEPLOYMENT_FAILED_ROLLBACK_FAILED
DEPLOYMENT_NOT_STARTED
```

A successful rollback does not convert a failed rollout into success. A rollback failure remains prominent and retains recovery lock state.

## Diagnose and audit

Run:

```bash
opshaven doctor
opshaven verify-audit
```

The deployment section distinguishes:

```text
no application registered
application registered but repository unavailable
application ready for planning
deployment plan available
deployment apply blocked
```

For a ready bundled sample, the next action is:

```bash
opshaven deploy plan sample-api
```

Malformed command syntax is explained by the command that rejected it. `doctor` is reserved for genuine environmental or readiness blockers.

Application registration, plan creation or rejection, approval, apply start, operation results, verification, deployment outcome, rollback start, and rollback result remain in the existing tamper-evident audit chain. Audit evidence uses bounded structured fields and digests rather than secrets, tokens, environment values, or raw build output.

## Normal completed sequence

```bash
opshaven init
opshaven setup remote
opshaven app add
opshaven deploy plan sample-api
opshaven deploy apply <plan-id>
opshaven doctor
opshaven boundary verify
```

Run `opshaven setup remote` again after registration only when the CLI specifically reports that the updated application authorization has not yet been installed.

## Terminal and automation behavior

Application registration, deployment planning, apply results, rollback outcomes, stale-plan rejection, replay rejection, authorization rejection, and validation failures use the same terminal presentation layer as initialization, setup, and doctor.

Color is presentation only:

```bash
NO_COLOR=1 opshaven deploy plan sample-api
OPSHAVEN_COLOR=never opshaven app add
```

Non-TTY output remains readable. JSON output contains no ANSI escape sequences.

## Unsupported deployment types

This profile does not support:

```text
database migrations
secret rotation
arbitrary hooks or arbitrary shell commands
containers or Kubernetes
cloud provisioning
multi-host or multi-service coordination
application auto-discovery
moving Git references
AI-generated deployment operations
web-dashboard deployment controls
```

A deployment requiring one of these features must not be forced through the supported profile.

## Security boundary

Private SSH and authorization material remains on the operator machine. The remote account has no interactive shell. Deployment is constrained to reviewed resource mappings, complete immutable revisions, and typed operations.

OpsHaven does not claim absolute security or universal deployment safety. Its guarantees still depend on the host kernel, filesystem ownership, OpenSSH, Git, Node.js, npm, systemd, configured resource mappings, health endpoint correctness, operator-owned keys, and the reviewed application build behaving as configured.
