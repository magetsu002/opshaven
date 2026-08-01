# OpsHaven

**Let AI troubleshoot your Linux VPS without giving it a shell.**

OpsHaven is a professional operator CLI and MCP server for approved Linux inspection and controlled operations over restricted SSH. Operators use normal terminal commands; generated configuration, keys, authorization data, receipts, and runtime verification stay behind the CLI.

## Operator workflow

A normal installation follows four commands:

```bash
opshaven init
opshaven setup remote
opshaven doctor
opshaven boundary verify
```

You do not need to run files from `dist`, edit generated JSON, inspect PEM files, or calculate internal runtime hashes.

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
- the administrator account used only for installation;
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
- rollback after failed post-install verification;
- tamper-evident audit history;
- independent installed-boundary verification.

OpsHaven does not claim absolute security. Its boundary still depends on the VPS kernel, OpenSSH, Node.js, systemd, configured resource mappings, identity provider, proxy or tunnel, and operator-owned keys behaving as configured.

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

Start the MCP protocol process only when testing an MCP client:

```bash
npm run start:mcp -- --config /absolute/path/to/generated-config.json
```

## Documentation

Read the [operator workflow](docs/operator-workflow.md) for the normal command sequence and the [setup guide](docs/setup.md) for host identity preparation, automation, rollback, and troubleshooting.

See the [security guide](docs/security.md) for the enforced boundary and the [architecture guide](docs/architecture.md) for implementation details. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). OpsHaven is provided under the [MIT License](LICENSE).
