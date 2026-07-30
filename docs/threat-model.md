# Threat model

## Protected assets

SSH keys, host identity, environment values, service credentials, deployment integrity, release history, approval authority, and audit evidence.

## Primary adversaries

- a prompt-injected or compromised AI client;
- an attacker who can call MCP tools but lacks human approval authority;
- an attacker who obtains the restricted SSH private key;
- malicious log or command output designed to exfiltrate secrets or exhaust memory;
- configuration tampering, symlink substitution, path traversal, or host-key replacement;
- replay, argument mutation, state drift, and race attempts around approvals;
- a compromised unprivileged service account attempting privilege expansion.

## Mitigations

- no arbitrary shell or user-selected executable, flags, service name, filesystem path, URL query, SQL, or script;
- strict unknown-field rejection at every protocol and configuration boundary;
- local logical-ID resolution plus independent remote logical-ID resolution;
- forced command at both authorized-key and sshd policy levels;
- pinned host keys with batch mode and forwarding disabled;
- exact-state approval digest, short expiry, local atomic consumption, remote signature verification, and remote atomic replay marker;
- fixed executable paths and argument arrays with `shell: false`;
- non-symlink configuration and trusted-file reads with open-time identity recheck;
- byte, line, input, and timeout bounds plus binary rejection;
- avoidance of environment values, proxy config dumps, and secret files whenever metadata is sufficient;
- redaction both remotely and locally;
- atomic release symlink activation and prior-activation restoration on failed health verification;
- hash-chained audit records and verification command.

## Explicit non-goals

OpsHaven V1 is not a remote shell, terminal, generic fleet manager, database console, secrets manager, arbitrary deployment runner, or replacement for host hardening. A root compromise can defeat an unprivileged dispatcher and remains outside the boundary.
