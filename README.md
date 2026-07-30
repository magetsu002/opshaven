# OpsHaven

OpsHaven is a local, general-purpose MCP server that gives AI agents safe VPS inspection and narrowly controlled operations over restricted SSH.

```text
AI client
→ local stdio MCP server
→ strict policy and human approval
→ host-key-pinned restricted SSH
→ VPS forced-command dispatcher
→ fixed allowlisted handlers
→ doubly redacted structured response
→ tamper-evident audit chain
```

## Safety model

OpsHaven never exposes a shell, arbitrary command, free-form path, SQL input, deployment script, generic container exec, or unrestricted file read. MCP tools accept only configured logical resource IDs and small typed arguments. Read operations are the default. Every real mutation requires a fresh expiring approval bound to the exact normalized arguments, configured target, policy version, and remote state fingerprint. The remote dispatcher verifies the approval signature independently and prevents replay.

## V1 tools

Inspection: `get_host_summary`, `get_deployed_commit`, `get_service_status`, `get_container_status`, `get_runtime_config_status`, `get_reverse_proxy_summary`, `get_firewall_summary`, `run_health_probe`, `get_redacted_logs`, `get_monitoring_status`, `get_backup_status`, and `get_restore_readiness`.

Controlled mutations: `restart_service`, `deploy_commit`, and `rollback_deployment`.

## Development

```bash
npm install --ignore-scripts --no-audit --no-fund
npm run check
```

The server is stdio-only:

```bash
npm run build
node dist/src/index.js --config /absolute/path/to/local.config.json
```

See `docs/setup.md` before connecting an MCP client. The repository remains at release-candidate version until exact-head CI and disposable-VPS certification pass; no `v1.0.0` tag should be created earlier.
