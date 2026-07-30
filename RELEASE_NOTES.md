# OpsHaven v1.0.0

OpsHaven is a local MCP server that gives AI agents safe, structured access to Linux VPS deployments without exposing a general-purpose shell.

## What’s included

- Structured inspection of hosts, services, containers, deployed commits, runtime configuration, reverse proxies, firewalls, logs, monitoring, and backups
- Restricted SSH access through a dedicated non-root account and VPS-side dispatcher
- Logical resource IDs instead of arbitrary commands or filesystem paths
- Secret-safe runtime checks and bounded log output
- Human-approved service restarts, Git deployments, and rollbacks
- Health verification and automatic restoration after failed deployments
- Tamper-evident audit logging
- Support for systemd, Docker Compose, Nginx, UFW, nftables, PostgreSQL backup checks, and Git-based deployments

## Security

OpsHaven is read-only by default. Mutating operations require explicit, short-lived approval and are validated on both the local MCP server and the VPS.

It does not provide arbitrary shell access or agent-defined command execution.

## V1 scope

OpsHaven currently runs as a local stdio MCP server and supports configured Linux VPS environments using systemd and Docker Compose.

See the repository documentation for setup, security boundaries, supported operations, and known limitations.
