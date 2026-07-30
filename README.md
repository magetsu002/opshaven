# OpsHaven

OpsHaven is a standalone MCP server for safe, structured VPS inspection and controlled operations through a restricted SSH account and an independently validating remote dispatcher.

The V1 implementation is security-first: logical resource IDs, read-only defaults, exact human approval for mutations, bounded secret-safe output, host-key verification, and tamper-evident audit records.

## Status

V1 is under active milestone-based implementation. Release tags are created only after clean-machine and disposable-VPS certification passes at the exact commit.

## Development

```bash
npm ci
npm run check
```

See [`docs/architecture.md`](docs/architecture.md) and [`docs/security.md`](docs/security.md) as the implementation progresses.
