# OpsHaven

OpsHaven is a local MCP server for inspecting and operating Linux VPS deployments through restricted SSH.

It gives AI agents access to predefined infrastructure actions without exposing a general-purpose shell.

## How it works

```text
AI client
→ local MCP server
→ policy and approval checks
→ restricted SSH account
→ VPS operation dispatcher
→ structured response
→ audit log
```

OpsHaven uses configured resource IDs instead of arbitrary commands, service names, or filesystem paths.

Read operations are allowed by default. Changes such as restarting a service, deploying a commit, or rolling back a release require explicit approval.

## Supported operations

### Inspection

- Host and deployed commit information
- systemd service status
- Docker and Docker Compose status
- Runtime configuration presence
- Nginx configuration summaries
- Firewall summaries
- Health probes
- Redacted logs
- Monitoring status
- Backup status
- Restore readiness

### Controlled changes

- Restart a configured service
- Deploy an exact Git commit
- Roll back to a recorded release

## Safety

OpsHaven does not provide arbitrary shell access.

The local server and the VPS dispatcher both validate every request. Runtime configuration checks return presence information only, and logs are bounded and redacted before they reach the AI client.

SSH connections use a dedicated non-root account, pinned host keys, and a forced-command dispatcher.

## Setup

See the [setup guide](docs/setup.md) to:

- install OpsHaven;
- configure the local MCP server;
- create the restricted VPS account;
- register VPS resources;
- connect an MCP client.

Review the [security guide](docs/security.md) before configuring SSH, sudo, deployment access, or production resources.

## Development

Requirements:

```text
Node.js 22 or newer
```

Install dependencies and run the full validation suite:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
```

Build and start the local stdio MCP server:

```bash
npm run build
node dist/src/index.js --config /absolute/path/to/local.config.json
```

## Project links

[Setup](docs/setup.md) · [Security](docs/security.md) · [Contributing](CONTRIBUTING.md) · [License](LICENSE)
