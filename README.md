# OpsHaven

OpsHaven is a standalone Model Context Protocol server for safe, structured VPS inspection and controlled operations over restricted SSH. It deliberately does **not** expose a shell, generic command runner, file browser, SQL interface, Docker exec, or public network listener.

```text
AI client
  -> local stdio MCP server
  -> policy and exact-approval layer
  -> pinned restricted SSH transport
  -> VPS forced-command dispatcher
  -> allowlisted typed handler
  -> sanitized structured result
  -> local tamper-evident audit log
```

## Security model

* Agents address configured logical resource IDs only.
* Unknown tools, fields, resources, remote messages, and states fail closed.
* Read operations are the default; every non-dry-run mutation requires an expiring single-use approval bound to the exact resolved operation.
* SSH uses a dedicated key and account, strict host-key verification, no PTY, no forwarding, and one forced dispatcher command.
* The remote dispatcher independently validates the request and resolves every executable, unit, path, URL, and deployment step from root-owned configuration.
* Environment values are never returned. Logs and errors are bounded, binary-rejected, and redacted before they cross the VPS boundary and again locally.
* Every decision and outcome is chained into an append-only audit log.

## V1 tools

Inspection:

`get_host_summary`, `get_deployed_commit`, `get_service_status`, `get_container_status`, `get_runtime_config_status`, `get_reverse_proxy_summary`, `get_firewall_summary`, `run_health_probe`, `get_redacted_logs`, `get_monitoring_status`, `get_backup_status`, and `get_restore_readiness`.

Controlled mutations:

`restart_service`, `deploy_commit`, and `rollback_deployment`.

## Development

Requirements: Node.js 22 or newer. OpenSSH client tools are required for real transport checks; Docker is required for the disposable restricted-SSH integration suite.

```sh
npm install --ignore-scripts
npm run check
npm run test:security
npm run security:scan
```

Run the real restricted-SSH fixture with:

```sh
npm run test:integration
```

Build and start the local stdio server:

```sh
npm run build
node dist/index.js --config /absolute/private/path/opshaven.config.json
```

Start with [`docs/setup.md`](docs/setup.md) and [`docs/mcp-client.md`](docs/mcp-client.md).

## Documentation

* [Architecture](docs/architecture.md)
* [Threat model](docs/threat-model.md)
* [Security controls](docs/security.md)
* [Configuration](docs/configuration.md)
* [Dispatcher boundary](docs/dispatcher.md)
* [Operations runbook](docs/operations.md)
* [Deployment and rollback](docs/deployment.md)
* [Release certification](docs/release.md)
* [Contributing](CONTRIBUTING.md)

## Release status

The implementation remains unreleased until the exact candidate commit passes clean-install, full validation, security, CodeQL, MCP startup, and disposable restricted-SSH certification. A `v1.0.0` tag must never be created from an uncertified commit.

Licensed under Apache-2.0.
