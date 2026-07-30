# Architecture

OpsHaven is designed around one principle: an AI client should never receive more authority than the VPS operator explicitly approves.

## Trust boundaries

1. **AI client:** treated as untrusted. Tool names, arguments, and output handling may be malicious or prompt-injected.
2. **Local MCP process:** validates JSON-RPC, strict tool schemas, logical IDs, policy, capability compatibility, authenticated responses, and audit records.
3. **Operator authority:** operator-owned Ed25519 keys sign capabilities and controlled approvals. Private authority remains outside the AI process and VPS dispatcher.
4. **SSH transport:** fixed `/usr/bin/ssh` executable and fixed arguments, pinned known-hosts file, no PTY, forwarding, shell command, or agent forwarding.
5. **Remote dispatcher:** a forced command under a dedicated non-root account. It rejects arbitrary SSH commands, verifies authenticated envelopes and signed capabilities, re-resolves logical IDs, and invokes only fixed handlers.
6. **Operating-system boundary:** root-owned dispatcher and trust files, strict modes, symlink-safe reads, artifact verification, private state, and confinement controls. Controlled mode receives only exact reviewed exceptions.
7. **Evidence boundary:** authenticated responses, remote and local data minimization, bounded structured output, and a local hash-chained audit log.
8. **Update boundary:** each build declares its authority. Capability comparison and operator signatures prevent a future client or release from silently expanding VPS access.

## Two dispatcher modes

### Isolated read-only dispatcher

The read-only build omits restart, deployment, rollback, approval-consumption, sudo, and Docker control handlers. Its reference launcher uses no-new-privileges and an empty capability set.

This is the recommended first installation because the dangerous controlled-mode code paths are absent rather than disabled by a runtime toggle.

### Controlled dispatcher

The controlled build supports approved restart, deployment, and rollback operations. Those paths require separate short-lived approvals bound to exact arguments and expected state.

Controlled mode may need narrowly scoped deployment writes, configured health-probe networking, rootless container access, and exact sudo rules. These are explicit exceptions and must appear in the build declaration and operator-reviewed configuration.

## Authenticated operation flow

```text
AI requests a logical operation
→ local schema and policy validation
→ operator-signed capability check
→ signed request envelope with nonce and expiry
→ pinned restricted SSH transport
→ remote capability and envelope verification
→ fixed handler over configured resources
→ remote minimization and redaction
→ signed response bound to the request
→ local response verification
→ audit record
```

A stolen restricted SSH key cannot produce a valid unsigned request or escape the forced-command dispatcher. A compromised local client cannot request operations or resources outside the operator-signed manifest.

## Component layout

- `config.ts`: strict versioned resource configuration and cross-reference validation.
- `policy.ts`: operation contracts, resource-kind authorization, typed argument normalization, limits, and dry-run semantics.
- `capabilities.ts`: signed operator capability manifests and build authority declarations.
- `protocol.ts`: canonical authenticated request and response envelopes, expiry, nonce, and replay checks.
- `approval.ts`: exact operation digest, local replay prevention, and Ed25519 mutation authorization.
- `transport/ssh.ts`: restricted host-key-verified SSH transport.
- `remote/read-only-dispatcher.ts`: isolated inspection-only forced-command entrypoint.
- `remote/dispatcher.ts`: controlled forced-command entrypoint.
- `remote/handlers.ts`: bounded inspection handlers and remote data minimization.
- `remote/mutations.ts`: remote approval enforcement and mutation routing.
- `remote/confinement.ts`: trusted-file, ownership, mode, path, and artifact verification.
- `remote/deployment.ts`: exact-commit preparation, activation, health verification, restoration, and recorded rollback.
- `redaction.ts`: binary rejection, credential and fingerprint redaction, control-character handling, and line and byte bounds.
- `audit.ts`: append-only hash chain and verifier.
- `mcp.ts`: local stdio MCP adapter with strict schemas.
- `cli.ts`: operator commands including `verify-boundary`, capability comparison, and `trust-report`.

## Deployment state machine

```text
validate clean repository
→ optionally fetch configured refs
→ resolve exact commit
→ prove commit is under an allowed ref
→ create isolated Git worktree
→ run configured fixed build/check steps
→ atomically switch current activation
→ activate configured systemd or rootless Compose target
→ run configured probes
→ restore the previous activation on failure
→ record release evidence
```

Database migrations are never automatically run or reversed. A manual migration policy is surfaced as risk evidence.

## Supply-chain boundary

The release pipeline uses full-SHA-pinned workflow actions, lockfile verification, deterministic archives, checksums, CycloneDX SBOM output, provenance, and Ed25519 artifact signatures.

These controls prove artifact identity and declared build inputs. They do not prove that the code is vulnerability-free or that the operator host is uncompromised.

## Verifying an installation

`opshaven verify-boundary` actively tests expected denials and integrity checks. `opshaven trust-report` presents the active mode, allowed authority, artifact and capability status, boundary result, and remaining assumptions in plain text or JSON.

Operators should rely on those results, reviewed OS permissions, and independent inspection rather than trusting a marketing claim.
