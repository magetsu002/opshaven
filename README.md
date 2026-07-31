# OpsHaven

**Let AI troubleshoot your Linux VPS without giving it a shell.**

OpsHaven is an MCP server that gives AI clients structured access to approved VPS operations through restricted SSH. You choose the resources, capabilities, keys, and update policy. OpsHaven enforces that boundary locally and again on the server.

## What it feels like

```text
You: Why is my website returning 502?

AI through OpsHaven:
- application service is running
- health probe passes on port 3001
- Nginx points to port 3000
- likely cause: reverse-proxy upstream mismatch
- no changes were made
```

Instead of opening an SSH session, checking several tools manually, and copying logs into a chat, you can ask a question and let the AI inspect only the signals you approved.

## Why operators can verify the boundary

OpsHaven does not ask you to trust the project author with your server.

- You generate and own the SSH, approval, capability, response-signing, and OAuth configuration.
- A separate read-only dispatcher contains no restart, deployment, rollback, sudo, or Docker control handlers.
- Operator-signed capability manifests bind the exact operations, resources, limits, policy version, and dispatcher identity.
- Requests and responses are authenticated, time-bounded, and replay-resistant.
- The dispatcher accepts logical resource IDs, not arbitrary commands, paths, services, scripts, or flags.
- Sensitive sources are summarized, bounded, and redacted before they reach the AI client.
- Future builds declare their capabilities so authority expansion can be detected and blocked.
- `opshaven boundary verify` tests the installed restrictions.
- `opshaven authorization-report` explains the active boundary and remaining assumptions.

OpsHaven does not claim absolute security. The operator still trusts the VPS kernel, OpenSSH, Node.js, systemd, configured resource mappings, identity provider, proxy or tunnel, and operator-owned keys.

## Executables

OpsHaven intentionally separates the human interface from the protocol process:

```text
opshaven
    Human CLI for setup, diagnostics, verification, reports, and approvals.

opshaven-mcp
    JSON-RPC MCP protocol server launched by an MCP client.
```

Use `opshaven help` in a terminal. Configure an MCP client with `opshaven-mcp`; do not run it expecting an interactive prompt.

The package scripts make the same distinction:

```bash
npm run cli -- help
npm run start:mcp -- --config /absolute/path/to/local.config.json
```

`npm start` prints human CLI help rather than starting a protocol server.

## How it works

### Local stdio

```text
Local AI client
→ local OpsHaven stdio MCP server
→ policy and authenticated request checks
→ restricted SSH account
→ independently validating VPS dispatcher
→ bounded authenticated response
→ audit log
```

The `opshaven-mcp` command is stdio-only and starts no network listener.

### Opt-in remote MCP

```text
Hosted MCP client
→ HTTPS tunnel or trusted reverse proxy
→ localhost-bound OpsHaven Streamable HTTP server
→ OIDC bearer verification and operator profile mapping
→ signed read-only capability intersection
→ restricted SSH read-only dispatcher
→ bounded authenticated response
→ audit log
```

Remote MCP is disabled by default, binds to `127.0.0.1` when enabled, requires an external OAuth/OIDC provider, and exposes only the effective intersection of the operator profile and signed read-only capability. Direct public binding and generic stdio relays are outside the reviewed boundary.

## Supported operations

### Inspection

- Host and deployed commit information
- systemd service status
- Docker and Docker Compose status in controlled local mode
- Runtime configuration presence
- Nginx and firewall summaries
- Health probes
- Bounded, redacted logs
- Monitoring and backup status
- Restore readiness

### Controlled local changes

- Restart a configured service
- Deploy an exact Git commit
- Restore the previous activation after failed health verification
- Roll back to a recorded release

Remote profiles cannot include these mutation tools.

## Recommended first run

Prepare reviewed local policy, setup, SSH, and signing-key files, then preview every VPS mutation:

```bash
opshaven setup remote \
  --dry-run \
  --config /absolute/path/to/remote-setup.json
```

Apply the same plan interactively or in explicit non-interactive automation:

```bash
opshaven setup remote --tui --config /absolute/path/to/remote-setup.json

opshaven setup remote \
  --non-interactive \
  --approve \
  --config /absolute/path/to/remote-setup.json
```

The setup command pins the host key, verifies the exact source head and signing key pair, installs the complete read-only runtime atomically, generates signed authorization artifacts locally, keeps private operator keys off the VPS, and refuses endpoint handoff until boundary certification passes.

```bash
opshaven doctor --config /absolute/path/to/local.config.json
opshaven boundary verify \
  --config /absolute/path/to/local.config.json \
  --setup-config /absolute/path/to/remote-setup.json
```

Rollback and uninstall require explicit approval:

```bash
opshaven setup remote --rollback --approve --config /absolute/path/to/remote-setup.json
opshaven uninstall remote --approve --config /absolute/path/to/remote-setup.json
```

See the [setup guide](docs/setup.md) for the reviewed configuration schema and end-to-end workflow, and the [security guide](docs/security.md) for the security boundary. The [architecture guide](docs/architecture.md) explains the enforcement layers in more detail.

## Development

Requirements:

```text
Node.js 22 or newer
```

Install dependencies and run the full validation suite:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
npm run reproducible:check
```

Build and inspect the human CLI:

```bash
npm run build
npm run cli -- help
```

Start the local stdio MCP server only when testing the protocol process:

```bash
npm run start:mcp -- --config /absolute/path/to/local.config.json
```

The native remote command is explicit and uses the reviewed companion configuration:

```bash
opshaven serve \
  --transport streamable-http \
  --config /absolute/path/to/local.config.json
```

## Project links

[Setup](docs/setup.md) · [Security](docs/security.md) · [Architecture](docs/architecture.md) · [Contributing](CONTRIBUTING.md) · [License](LICENSE)
