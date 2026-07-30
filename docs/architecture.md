# Architecture

## Trust boundaries

1. **AI client:** untrusted tool names and arguments.
2. **Local MCP process:** validates JSON-RPC, strict tool schemas, logical IDs, and policy.
3. **Human approval store:** protected local HMAC state plus an Ed25519 signing key. Tokens are expiring and single-use.
4. **SSH transport:** fixed `/usr/bin/ssh` executable and fixed arguments, pinned known-hosts file, no PTY, forwarding, shell command, or agent forwarding.
5. **Remote dispatcher:** a forced command under a dedicated non-root account. It rejects `SSH_ORIGINAL_COMMAND`, validates one bounded JSON request, re-resolves logical IDs, and invokes only fixed handlers.
6. **Privileged boundary:** only exact reviewed `sudo` rules for configured systemd units. Docker Compose activation requires rootless Docker owned by the restricted account; membership in a privileged system Docker group is outside the safe V1 model.
7. **Evidence boundary:** remote and local redaction, bounded structured envelopes, and a local hash-chained audit log.

## Component layout

- `config.ts`: strict versioned resource configuration and cross-reference validation.
- `policy.ts`: operation contracts, resource-kind authorization, typed argument normalization, limits, dry-run semantics.
- `approval.ts`: exact operation digest, local replay prevention, Ed25519 remote authorization.
- `transport/ssh.ts`: restricted host-key-verified SSH transport.
- `remote/dispatcher.ts`: one-request forced-command entrypoint.
- `remote/handlers.ts`: read-only inspection handlers.
- `remote/mutations.ts`: remote approval enforcement and mutation routing.
- `remote/deployment.ts`: exact-commit release preparation, activation, verification, reversion, and recorded rollback.
- `redaction.ts`: binary rejection, credential redaction, fingerprint redaction, line and byte bounds.
- `audit.ts`: append-only hash chain and verifier.
- `mcp.ts`: stdio MCP adapter with strict schemas.

## Deployment state machine

```text
validate clean repository
→ optionally fetch configured refs
→ resolve exact commit
→ prove commit is under an allowed ref
→ create isolated Git worktree
→ run configured fixed build/check steps
→ atomically switch current symlink
→ activate configured systemd or rootless Compose target
→ run configured probes
→ record release evidence
```

A failed build, activation, or probe restores the previous activation when one exists. Database migrations are never automatically run or reversed. A manual migration policy is surfaced as risk evidence.
