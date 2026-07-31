# Security

OpsHaven gives AI clients useful VPS visibility and narrowly controlled operations without giving them a general-purpose shell.

The operator owns the keys, capability policy, resource mappings, installation, updates, remote identity policy, and proxy or tunnel configuration. OpsHaven makes that authority visible, testable, and independently enforced on the VPS.

## Recommended deployment posture

Start with the isolated read-only dispatcher on a disposable VPS.

In that mode, use:

- no mutation handlers;
- no sudo permissions;
- no application or deployment write access;
- no system Docker socket access;
- no shell, PTY, forwarding, or arbitrary SSH command execution;
- only explicitly configured logical resources;
- operator-owned capability authorization;
- `opshaven boundary verify` before connecting an AI client;
- `opshaven authorization-report` to review the active boundary.

Move to controlled mode only when restart, deployment, or rollback authority is actually needed and its exact privileges have been reviewed. Controlled mutation tools remain unavailable through the remote MCP transport.

## Operator ownership

Keep SSH private keys, approval signing material, capability-signing keys, release keys, configuration, known-hosts files, OAuth policy, and audit state private. Key material should be owned by the local user with mode `0600`.

Configuration and signed policy artifacts should be regular files rather than symlinks. Approval and audit directories should only be accessible to the operator.

Only required public keys and narrowly scoped response-signing material belong on the VPS. The project author does not need access to the server, credentials, policy, or logs.

## Restricted SSH account

Use a dedicated non-root account with public-key authentication, a forced command, no interactive shell, no PTY, and no agent, TCP, X11, or tunnel forwarding. Apply restrictions in both `authorized_keys` and an `sshd` `Match User` rule.

The dispatcher rejects arbitrary SSH command text and accepts only one bounded authenticated request envelope.

Possession of the restricted SSH key must not authorize a change. Controlled mutations require a separate short-lived approval bound to the exact operation, target, arguments, expected state, and expiry. Approvals are consumed once and verified again on the VPS.

## Capability authorization

The operator-signed capability authorization binds the allowed operations, logical resources, output limits, policy version, expiry, and dispatcher identity.

The VPS rejects missing, altered, expired, incompatible, or non-canonical authorization data. A future local client or project update cannot silently gain remote authority without newly accepted operator authorization.

Each build also declares its non-API authority, including handlers, filesystem access, executables, network requirements, sudo requirements, and output fields. Capability comparison makes permission growth visible before adoption.

Remote MCP requires separately signed read-only capability authorization. The authenticated principal profile and signed authorization are intersected per tool and per logical resource. A tool or resource must be present in both authorities before it appears in discovery or can execute.

## Authenticated protocol

Requests bind the validated operation, resource, arguments, capability hash, dispatcher hash, nonce, issue time, and expiry. The dispatcher rejects unsigned, stale, replayed, modified, or mismatched requests.

Responses bind the originating request hash, result hash, active capability, dispatcher identity, and timestamp. The local process rejects unsigned, altered, stale, or mismatched responses.

SSH encrypts transport. These signatures add end-to-end integrity and authority binding, but they do not protect an endpoint whose runtime or private keys are already compromised.

## Remote MCP entrance

Remote MCP is disabled when the reviewed companion configuration is absent. Enabling it starts only an explicitly requested Streamable HTTP listener. The supported deployment keeps that listener on loopback and exposes only the configured MCP path through a reviewed HTTPS tunnel or explicitly configured reverse proxy.

Every request passes these boundaries before MCP or SSH processing:

- bounded header count and bytes;
- OAuth/OIDC bearer verification with a configured algorithm allowlist;
- exact issuer, audience, expiry, not-before, issue-time, and scope checks;
- immutable issuer-and-subject principal identity;
- operator-owned subject-to-profile mapping;
- exact HTTPS Origin allowlist;
- exact Host allowlist;
- forwarding headers accepted only from configured proxy addresses;
- request-body and JSON structural limits;
- global and per-principal rate and concurrency limits;
- protocol and session validation;
- signed read-only capability intersection.

Tokens in query strings are rejected. Raw bearer tokens are not included in logs, errors, audit records, responses, URLs printed by the CLI, fixtures, or generated artifacts. Provider discovery and JWKS retrieval use bounded HTTPS requests, exact issuer matching, an explicit JWKS host allowlist, bounded caches, and fail-closed refresh behavior.

The finalized stateless MCP revision rejects session headers. Older supported revisions use cryptographically random in-memory sessions bound to the authenticated principal, profile, and protocol revision. Sessions have bounded lifetimes, inactivity limits, pending-request limits, replay protection, and are cleared on shutdown.

Request timeout or client disconnect propagates cancellation to the operation service and restricted SSH child. The server bounds request, response, queue, connection, and idle resources before expensive work.

The remote transport never accepts runtime configuration paths, SSH identities, executable paths, service names, repository paths, environment assignments, SQL, scripts, shell text, or profile selection from the client. It exposes no SSH, dispatcher, Docker, Podman, filesystem, configuration, diagnostics, or administrative HTTP endpoint.

Direct public binding, plaintext public exposure, wildcard origins or hosts, unauthenticated fallback, and generic stdio-to-HTTP bridges are outside the reviewed boundary. See [Secure remote MCP](remote-mcp.md).

## Secrets, logs, and resources

Prefer metadata over secret values. Runtime configuration checks report presence rather than values. Health probes should use credential-free URLs, and passwords or tokens must not appear in paths or query strings.

Logs are untrusted input. OpsHaven bounds and redacts them remotely and locally, and handles binary data, terminal control sequences, bidirectional text controls, zero-width characters, and output-injection attempts. Redaction remains defense in depth, not permission to store secrets in logs.

All services, deployments, paths, probes, and container targets must be predefined in configuration. The dispatcher does not accept arbitrary executables, flags, service names, filesystem paths, SQL, scripts, or shell commands.

## Remote confinement

The dispatcher artifact, policy, capability authorization, declarations, bindings, and public verification keys must be root-owned, strictly permissioned, non-symlink regular files at normalized paths. Runtime and declaration identities are checked before authenticated operations are served.

The isolated read-only launcher uses no-new-privileges and an empty capability set. The reference systemd profile adds private temporary space, filesystem protections, restricted address families, device isolation, and syscall filtering where supported.

Controlled mode intentionally requires narrowly documented exceptions for approved deployment writes, configured health-probe networking, and exact systemd sudo transitions. Distribution-specific systemd and syscall behavior must be validated before production adoption.

See [Remote confinement](confinement.md) for the detailed reference profile.

## Verifiable updates and releases

OpsHaven does not self-update. Operators should review capability changes, source changes, signed tags, checksums, provenance, SBOM data, and artifact signatures before installing a new build.

Authority expansion should block adoption until the operator deliberately accepts and signs compatible capability authorization.

See [Reproducible and verifiable releases](reproducible-builds.md) for build and artifact verification instructions.

## What OpsHaven protects against

The design specifically reduces risk from:

- a compromised or prompt-injected AI client;
- stolen restricted SSH credentials;
- arbitrary command and argument injection;
- malicious or oversized log output;
- capability, request, response, token, session, or approval mutation;
- replay and stale authenticated messages;
- path traversal, symlink substitution, and unsafe signed policy artifacts;
- silent permission growth across updates;
- deployment state drift and rollback-record tampering;
- unreviewed origins, hosts, forwarding headers, and cross-principal session reuse;
- request, response, JSON, queue, rate, concurrency, and timeout exhaustion.

## Remaining platform assumptions

OpsHaven is not a replacement for host hardening. The boundary still assumes a correctly controlled VPS kernel, OpenSSH, Node.js runtime, systemd installation, fixed system executables, operator-owned keys, logical-resource mappings, exact sudo configuration, OAuth issuer, DNS, HTTPS tunnel or configured proxy, and token revocation process.

A root-level host compromise, compromised operator machine, stolen signing key, compromised identity provider, malicious runtime or proxy, or incorrectly granted OS permission can break the intended boundary.

Use `opshaven authorization-report` to review the enforced boundary and remaining assumptions. Do not claim that any deployment is unhackable or absolutely safe.

See [Operator workflow](operator-workflow.md) for a concrete description of local components, remote components, keys, uploaded material, authorization, and MCP exposure.

## Validation

Before submitting changes, run:

```bash
npm run release:check
npm run security
npm run reproducible:check
integration/disposable-vps/run.sh
integration/remote-mcp-podman/run.sh
```

CI checks formatting, lint, strict type safety, both dispatcher builds, stdio and remote transport tests, package contents, documentation links, lockfile integrity, action pinning, reproducibility, dependency audit, secret scanning, CodeQL, the disposable restricted-SSH lifecycle, and rootless remote-MCP integration.

## Reporting a vulnerability

Follow [SECURITY.md](../SECURITY.md). Do not include real credentials, hostnames, IP addresses, customer information, private infrastructure details, or unrelated project identifiers in reports or fixtures.
