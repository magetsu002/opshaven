# Security

OpsHaven gives AI clients useful VPS visibility and narrowly controlled operations without giving them a general-purpose shell.

The goal is not to make the operator trust the project author. The operator owns the keys, capability policy, resource mappings, installation, and updates. OpsHaven makes that authority visible, testable, and independently enforced on the VPS.

## Recommended trust posture

Start with the isolated read-only dispatcher on a disposable VPS.

In that mode, use:

- no mutation handlers;
- no sudo permissions;
- no application or deployment write access;
- no system Docker socket access;
- no shell, PTY, forwarding, or arbitrary SSH command execution;
- only explicitly configured logical resources;
- operator-owned signed capability manifests;
- `opshaven verify-boundary` before connecting an AI client;
- `opshaven trust-report` to review the active boundary.

Move to controlled mode only when restart, deployment, or rollback authority is actually needed and its exact privileges have been reviewed.

## Operator ownership

Keep SSH private keys, approval signing material, capability-signing keys, release keys, configuration, known-hosts files, and audit state private. Key material should be owned by the local user with mode `0600`.

Configuration and trust files should be regular files rather than symlinks. Approval and audit directories should only be accessible to the operator.

Only required public keys and narrowly scoped response-signing material belong on the VPS. The project author does not need access to the server, credentials, policy, or logs.

## Restricted SSH account

Use a dedicated non-root account with public-key authentication, a forced command, no interactive shell, no PTY, and no agent, TCP, X11, or tunnel forwarding. Apply restrictions in both `authorized_keys` and an `sshd` `Match User` rule.

The dispatcher rejects arbitrary SSH command text and accepts only one bounded authenticated request envelope.

Possession of the restricted SSH key must not authorize a change. Controlled mutations require a separate short-lived approval bound to the exact operation, target, arguments, expected state, and expiry. Approvals are consumed once and verified again on the VPS.

## Signed capabilities

The operator-signed capability manifest binds the allowed operations, logical resources, output limits, policy version, expiry, and dispatcher identity.

The VPS rejects missing, altered, expired, incompatible, or non-canonical capability data. A future local client or project update cannot silently gain remote authority without a newly accepted operator manifest.

Each build also declares its non-API authority, including handlers, filesystem access, executables, network requirements, sudo requirements, and output fields. Capability comparison is intended to make permission growth visible before adoption.

## Authenticated protocol

Requests bind the validated operation, resource, arguments, capability hash, dispatcher hash, nonce, issue time, and expiry. The dispatcher rejects unsigned, stale, replayed, modified, or mismatched requests.

Responses bind the originating request hash, result hash, active capability, dispatcher identity, and timestamp. The local process rejects unsigned, altered, stale, or mismatched responses.

SSH already encrypts transport. These signatures add end-to-end integrity and authority binding, but they do not protect an endpoint whose trusted runtime or private keys are already compromised.

## Secrets, logs, and resources

Prefer metadata over secret values. Runtime configuration checks report presence rather than values. Health probes should use credential-free URLs, and passwords or tokens must not appear in paths or query strings.

Logs are untrusted input. OpsHaven bounds and redacts them remotely and locally, and handles binary data, terminal control sequences, bidirectional text controls, zero-width characters, and output-injection attempts. Redaction remains defense in depth, not permission to store secrets in logs.

All services, deployments, paths, probes, and container targets must be predefined in configuration. The dispatcher does not accept arbitrary executables, flags, service names, filesystem paths, SQL, scripts, or shell commands.

## Remote confinement

The dispatcher artifact, policy, capability manifest, declarations, and trust files must be root-owned, strictly permissioned, non-symlink regular files at normalized paths. Artifact and declaration identities are checked before authenticated operations are served.

The isolated read-only launcher uses no-new-privileges and an empty capability set. The reference systemd profile adds private temporary space, filesystem protections, restricted address families, device isolation, and syscall filtering where supported.

Controlled mode intentionally requires narrowly documented exceptions for approved deployment writes, configured health-probe networking, and exact systemd sudo transitions. Distribution-specific systemd and syscall behavior must be validated before production adoption.

See [Remote confinement](remote-confinement.md) for the detailed reference profile.

## Verifiable updates and releases

OpsHaven does not self-update. Operators should review capability changes, source changes, signed tags, checksums, provenance, SBOM data, and artifact signatures before installing a new build.

Authority expansion should block adoption until the operator deliberately accepts and signs a compatible capability manifest.

See [Reproducible and verifiable releases](releases.md) for build and artifact verification instructions.

## What OpsHaven protects against

The design specifically reduces risk from:

- a compromised or prompt-injected AI client;
- stolen restricted SSH credentials;
- arbitrary command and argument injection;
- malicious or oversized log output;
- capability, request, response, or approval mutation;
- replay and stale authenticated messages;
- path traversal, symlink substitution, and unsafe trust files;
- silent permission growth across updates;
- deployment state drift and rollback-record tampering.

## Remaining assumptions

OpsHaven is not a replacement for host hardening. The boundary still assumes a trustworthy VPS kernel, OpenSSH, Node.js runtime, systemd installation, fixed system executables, operator-owned keys, logical-resource mappings, and exact sudo configuration.

A root-level host compromise, compromised operator machine, stolen signing key, malicious trusted runtime, or incorrectly granted OS permission can break the intended boundary.

Use `opshaven trust-report` to review the enforced boundary and remaining assumptions. Do not claim that any deployment is unhackable or absolutely safe.

## Validation

Before submitting changes, run:

```bash
npm run release:check
npm run security
scripts/check-reproducible-build.sh
integration/disposable-vps/run.sh
```

CI checks formatting, lint, strict type safety, both dispatcher builds, tests, package contents, documentation links, lockfile integrity, action pinning, reproducibility, dependency audit, secret scanning, CodeQL, and the disposable restricted-SSH lifecycle.

## Reporting a vulnerability

Follow [SECURITY.md](../SECURITY.md). Do not include real credentials, hostnames, IP addresses, customer information, private infrastructure details, or unrelated project identifiers in reports or fixtures.
