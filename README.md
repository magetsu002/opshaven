# OpsHaven

**Let AI troubleshoot your Linux VPS without giving it a shell.**

OpsHaven is a local MCP server that gives AI clients structured access to approved VPS operations through restricted SSH. You choose the resources, capabilities, keys, and update policy. OpsHaven enforces that boundary locally and again on the server.

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

- You generate and own the SSH, approval, capability, and response-signing keys.
- A separate read-only dispatcher contains no restart, deployment, rollback, sudo, or Docker control handlers.
- Operator-signed capability manifests bind the exact operations, resources, limits, policy version, and dispatcher identity.
- Requests and responses are authenticated, time-bounded, and replay-resistant.
- The dispatcher accepts logical resource IDs, not arbitrary commands, paths, services, scripts, or flags.
- Sensitive sources are summarized, bounded, and redacted before they reach the AI client.
- Future builds declare their capabilities so authority expansion can be detected and blocked.
- `opshaven verify-boundary` tests the installed restrictions.
- `opshaven trust-report` explains the active boundary and remaining assumptions.

OpsHaven does not claim absolute security. The operator still trusts the VPS kernel, OpenSSH, Node.js, systemd, configured resource mappings, and operator-owned keys.

## How it works

```text
AI client
→ local OpsHaven MCP server
→ policy and authenticated request checks
→ restricted SSH account
→ independently validating VPS dispatcher
→ bounded authenticated response
→ audit log
```

Read operations are available by default. Controlled changes such as restarting a configured service, deploying an exact commit, or rolling back to a recorded release require explicit, short-lived approval.

## Supported operations

### Inspection

- Host and deployed commit information
- systemd service status
- Docker and Docker Compose status in controlled mode
- Runtime configuration presence
- Nginx and firewall summaries
- Health probes
- Bounded, redacted logs
- Monitoring and backup status
- Restore readiness

### Controlled changes

- Restart a configured service
- Deploy an exact Git commit
- Restore the previous activation after failed health verification
- Roll back to a recorded release

## Recommended first run

```text
1. Use a disposable VPS with no valuable data.
2. Install the isolated read-only dispatcher.
3. Register only the resources needed for one diagnosis.
4. Run opshaven verify-boundary.
5. Review opshaven trust-report.
6. Connect your MCP client.
7. Add controlled operations only after reviewing their exact authority.
```

See the [setup guide](docs/setup.md) for installation and the [security guide](docs/security.md) for the trust model. The [architecture guide](docs/architecture.md) explains the enforcement layers in more detail.

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
```

Build and start the local stdio MCP server:

```bash
npm run build
node dist/src/index.js --config /absolute/path/to/local.config.json
```

## Project links

[Setup](docs/setup.md) · [Security](docs/security.md) · [Architecture](docs/architecture.md) · [Contributing](CONTRIBUTING.md) · [License](LICENSE)
