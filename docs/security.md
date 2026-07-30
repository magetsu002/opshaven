# Security

OpsHaven gives AI agents useful VPS access without giving them a general-purpose shell. Its security depends on a local policy boundary, a restricted SSH account, an independently validating remote dispatcher, and explicit human approval for changes.

## Local machine

Keep SSH private keys, approval signing material, configuration, known-hosts files, and audit state private. Key material should be owned by the local user with mode `0600`. Configuration and key files should be regular files rather than symlinks, and approval or audit directories should only be accessible to the operator.

Generate approval keys with:

```bash
scripts/bootstrap-local.sh
```

Only the public approval key belongs on the VPS.

## Restricted SSH account

Use a dedicated non-root account with public-key authentication, a forced command, no interactive shell, no PTY, no forwarding, and only narrowly scoped sudo access. Apply restrictions in both `authorized_keys` and an `sshd` `Match User` rule.

Possession of the SSH key must not authorize a change. Mutating operations also require a short-lived signed approval bound to the exact target, arguments, and expected state. Approvals are consumed once and verified again by the VPS.

## Secrets, logs, and resources

Prefer metadata over secret values. Runtime configuration checks should report presence only. Health probes should use credential-free URLs, and passwords or tokens must not appear in paths or query strings.

Logs are untrusted input. OpsHaven bounds and redacts them before and after they cross the SSH boundary. Redaction is defense in depth, not permission to store secrets in logs. For especially sensitive values, configure SHA-256 fingerprints instead of the original values.

All services, deployments, paths, probes, and container targets must be predefined in configuration. The dispatcher does not accept arbitrary executables, flags, service names, filesystem paths, SQL, scripts, or shell commands.

## Threat model

OpsHaven protects SSH keys, host identity, environment values, service credentials, deployment integrity, release history, approval authority, and audit evidence.

The main threats are a compromised or prompt-injected AI client, stolen restricted SSH credentials, malicious log output, configuration tampering, path or symlink substitution, approval replay or mutation, state drift, and privilege expansion from the restricted account.

The primary controls are:

- independent logical-resource validation on both sides of SSH;
- pinned host keys and disabled forwarding;
- fixed executable paths and argument arrays without a shell;
- strict input schemas and bounded output;
- trusted-file checks that reject symlinks and identity changes;
- signed, expiring, single-use approvals tied to exact state;
- atomic deployment activation and rollback records;
- hash-chained audit records with verification.

OpsHaven is not a remote shell, database console, secrets manager, generic fleet manager, or replacement for host hardening. A root-level host compromise remains outside its protection boundary.

## Validation

Before submitting changes, run:

```bash
npm run release:check
npm run security
```

CI checks formatting, lint, strict type safety, tests, build output, package contents, documentation links, dependency audit, secret scanning, CodeQL, and the restricted-SSH integration.

## Reporting a vulnerability

Follow [SECURITY.md](../SECURITY.md). Do not include real credentials, hostnames, IP addresses, customer information, or private infrastructure details in reports or fixtures.
