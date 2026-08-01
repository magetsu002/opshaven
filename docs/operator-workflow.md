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

The wizard explains that it runs on the operator machine and does not install anything remotely. It asks for a friendly target name, SSH address, administrator account used only for installation, owner-only administrator key, pinned `known_hosts` source, independently verified host fingerprint, and final confirmation.

Example:

```text
OpsHaven first-time setup

Remote machine
Name [PRIMARY]: EXAMPLE
SSH address: example.invalid:22
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
  --host example.invalid \
  --port 22 \
  --admin-user ubuntu \
  --admin-identity "$HOME/.ssh/example-admin" \
  --known-hosts "$HOME/.ssh/known_hosts" \
  --host-key-sha256 "SHA256:verified-value" \
  --privilege sudo-noninteractive
```

Non-interactive setup never treats an automatically discovered fingerprint as operator approval. The expected fingerprint must be supplied after independent verification.

## Set up the remote machine

Run on the operator machine:

```bash
opshaven setup remote
```

The command identifies the target, performs exact preflight checks, installs the restricted runtime, configures authorization, verifies the boundary, and reports the next command. Preview without changes with:

```bash
opshaven setup remote --dry-run
```

Reviewed automation remains explicit:

```bash
opshaven setup remote --non-interactive --approve
```

Add `--debug` to display lower-level setup evidence. Normal output intentionally hides protected paths and implementation hashes.

## Register an application

The initial deployment profile is deliberately narrow: an existing Git repository on the approved host, fixed npm install and build operations, versioned release directories, an atomic active-release symlink, one approved systemd service, one bounded HTTP GET health check, and automatic restoration of the previous release.

Run:

```bash
opshaven app add
```

The guided command collects only operator-facing facts:

```text
Application name
Remote target
Repository location
Release location
Service identifier
Health check
Expected status
Rollback behavior
```

It rejects unsafe or overlapping paths, duplicate application IDs, malformed service identifiers, unsupported build strategies, credentials in health URLs, and arbitrary command input before persistence. Cancellation and validation failure create no partial state.

After registration, synchronize and verify the generated authorization at the restricted remote boundary:

```bash
opshaven setup remote
```

Synthetic example:

```text
Application: sample-api
Repository: /srv/opshaven-fixtures/sample-api/repository
Releases:   /srv/opshaven-fixtures/sample-api/releases
Service:    sample-api.service
Health:     http://127.0.0.1:3000/health
```

## Plan an exact revision

Create a read-only plan:

```bash
opshaven deploy plan sample-api --revision <full-commit-sha>
```

Only a complete 40-character Git commit SHA is accepted. Branches, tags, `HEAD`, `latest`, abbreviated SHAs, and arbitrary ref expressions are rejected. The restricted remote runtime verifies the exact commit belongs to the configured source before any deployment mutation.

Planning inspects only the active release, current exact revision, approved service state, health status, available disk, runtime availability, rollback release, and target revision membership. It does not build, fetch into active state, restart services, activate releases, run migrations, or change authorization.

The plan contains ordered typed operations, permitted resources, privilege requirements, timeouts, output bounds, redaction rules, mutation classes, verification steps, rollback steps, current and target revisions, target identity, policy and operation-definition digests, risk, expiration, and a nonce.

Its immutable identity is:

```text
sha256:<digest>
```

The digest covers the complete canonical plan. Repeating planning with unchanged configuration, requested revision, observed state, target identity, authorization policy, and operation definitions returns the same still-valid stored plan. A changed input or expired plan requires a new plan.

## Apply the exact plan

Run:

```bash
opshaven deploy apply <plan-id>
```

Interactive apply shows the exact release mutation, approved service restart, and prepared rollback, then defaults to `No`. Confirmation creates the existing one-time cryptographic authorization for the exact operation. Non-interactive apply requires an existing signed approval token; there is no casual `--yes` bypass.

Immediately before mutation, OpsHaven revalidates plan integrity and expiration, application and host identity, operator profile and policy version, operation definitions, current revision and observed-state fingerprint, rollback availability, disk, runtime, service identity, health status, and target commit membership. Any difference fails closed and requires a new plan.

Only one apply may hold an application's persistent lock. A started plan cannot be replayed. A rollback failure retains the lock as explicit recovery state.

## Activation and recovery

The constrained remote deployment engine verifies the source, creates a separate versioned release, runs only fixed bounded build steps, records the previous release, switches the active symlink atomically, and restarts only the approved systemd service.

Completion requires all checks:

```text
approved service active
health status accepted
expected release selected
exact target revision active
```

If post-activation verification fails, OpsHaven restores the recorded previous release, restarts the approved service, reruns health verification, and confirms the previous revision. It reports one of:

```text
DEPLOYMENT_SUCCEEDED
DEPLOYMENT_FAILED_ROLLED_BACK
DEPLOYMENT_FAILED_ROLLBACK_FAILED
DEPLOYMENT_NOT_STARTED
```

A successful rollback does not convert a failed rollout into success. A rollback failure is prominent and blocks conflicting deployment until recovery state is resolved.

## Diagnose and audit

Run:

```bash
opshaven doctor
opshaven verify-audit
```

`doctor` includes deployment configuration validity, remote release readiness, approved service availability, health reachability, rollback availability, the current blocker, and the next plan command. Normal output hides protected filenames.

Application registration, plan creation or rejection, apply approval and start, operation results, verification, deployment result, rollback start, and rollback result remain in the existing tamper-evident audit chain. Audit evidence uses bounded structured fields and digests rather than secrets, tokens, environment values, or raw build output.

## Verify and operate

After setup succeeds:

```bash
opshaven boundary verify
opshaven authorization-report --mode read-only
opshaven print-mcp-config
```

A normal completed sequence is:

```bash
opshaven init
opshaven setup remote
opshaven app add
opshaven setup remote
opshaven deploy plan sample-api --revision <full-commit-sha>
opshaven deploy apply <plan-id>
opshaven doctor
opshaven boundary verify
```

Rollback and uninstall of the OpsHaven runtime continue to use the protected setup record:

```bash
opshaven setup remote --rollback --approve
opshaven uninstall remote --approve
```

## Unsupported deployment types

This profile does not support database migrations, secret rotation, arbitrary hooks or shell commands, containers, Kubernetes, cloud provisioning, multi-host or multi-service coordination, application discovery, moving Git refs, AI-generated operations, or a web dashboard.

## Terminal and automation modes

Colors and symbols are presentation only. Text, exit codes, checks, and JSON remain authoritative.

```bash
NO_COLOR=1 opshaven doctor
OPSHAVEN_COLOR=never opshaven setup remote
```

Use `--json` where supported and `--debug` for lower-level diagnostics. Neither option weakens validation.

## Security boundary

Private SSH and authorization material remains on the operator machine. The remote account has no interactive shell. Deployment is constrained to reviewed resource mappings and typed operations, not arbitrary command execution.

OpsHaven does not claim absolute security or universal deployment safety. The guarantees depend on the host kernel, filesystem ownership, OpenSSH, Git, Node.js, npm, systemd, configured resource mappings, health endpoint correctness, operator-owned keys, and reviewed application build behaving as configured.
