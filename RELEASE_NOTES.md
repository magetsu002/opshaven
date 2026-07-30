# OpsHaven 1.0.0

OpsHaven 1.0.0 is the first stable release of the local, general-purpose MCP server for safe VPS inspection and narrowly controlled operations over restricted SSH.

## Safe structured inspection

V1 exposes typed MCP tools for host, service, container, deployment, runtime configuration, reverse proxy, firewall, health probe, logs, monitoring, backup, and restore-readiness evidence. Agents address configured logical resource IDs rather than commands, paths, flags, SQL, or scripts.

## Security model

The MCP server is stdio-only and read-only by default. SSH uses pinned host keys, a dedicated non-root account, no PTY or forwarding, and a VPS-side forced-command dispatcher that independently validates every request. Real mutations require an expiring, exact-state, single-use human approval that is verified and consumed again on the VPS. Output is bounded, binary-rejecting, and redacted on both sides of the SSH boundary.

## Secret-safe runtime and logs

Runtime configuration checks report presence metadata only and never return environment values. Log output redacts credentials, authorization headers, cookies, URLs, tokens, JWTs, keys, and configured secret fingerprints while enforcing strict byte, line, and timeout limits.

## Service and container activation

Configured systemd services are supported through exact reviewed sudo rules. Docker Compose activation is supported through a configured rootless Docker environment; membership in a root-equivalent system Docker group is outside the V1 safety model.

## Deployment and rollback

`deploy_commit` validates an exact commit under configured refs, refuses dirty or conflicting state, creates an isolated release, runs only configured trusted build and check steps, activates the release, restarts configured resources, and verifies configured health probes. Failed verification restores the prior activation. `rollback_deployment` can activate only a validated recorded release.

## Tamper-evident audit

Every completed, denied, or failed operation is recorded in a local append-only hash chain. The CLI verifier detects modified, reordered, missing, or malformed records.

## Certification

The release suite covers locked clean installation, formatting, lint, strict type checking, 43 focused and adversarial tests, compiled MCP startup, package and documentation inspection, dependency audit, tracked-file and Git-history scanning, CodeQL, real Docker and OpenSSH restrictions, and the complete approved deployment and rollback lifecycle.

## Known V1 limitations

- The MCP server is local stdio only and is not exposed as a network service.
- Deployment activation is limited to configured systemd and Docker Compose strategies.
- Docker Compose requires a safe rootless Docker setup.
- Database migrations are never automatically executed or reversed.
- Health probes must use credential-free configured HTTP or HTTPS URLs.
- Operators remain responsible for host hardening, key custody, exact sudo rules, backups, and migration compatibility.
- The repository does not publish an npm package in this release.
