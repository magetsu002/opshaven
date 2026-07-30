# Threat model

## Assets

OpsHaven protects VPS control, deployment integrity, application availability, credentials, runtime configuration, logs, SSH identity material, approval keys, release records, and audit evidence.

## Adversaries

The design assumes an AI agent, MCP client input, remote command output, network path, application logs, and a compromised non-root service may be malicious or malformed. The local administrator, root-owned configuration, root-owned dispatcher wrapper, operating system kernel, OpenSSH client/server, Node.js runtime, and explicitly configured build executables are part of the trusted computing base.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Prompt-driven command injection | No command field exists; tools accept logical IDs and narrow typed values only. |
| Unknown resource access | Strict lookup against configured IDs and host ownership. |
| Path traversal or symlink substitution | Normalized configured paths, non-symlink checks at sensitive local boundaries, safe release directories, and atomic activation. |
| SSH man-in-the-middle | Dedicated known-hosts file plus independent SHA-256 fingerprint verification. |
| Shell or forwarding escape | Forced command in two places, no PTY, no forwarding, no tunnels, no agent forwarding, no user rc. |
| Dispatcher bypass | No arguments, one bounded JSON request, independent policy resolution, immutable handler registry. |
| Secret exfiltration | Avoid environment values, body discard for probes, remote and local redaction, configured fingerprints, bounded output. |
| Output exhaustion or binary confusion | Time, byte, and line limits; UTF-8 and single-envelope validation; process termination on overflow. |
| Approval mutation or replay | Canonical exact-operation digest, HMAC, expiry, nonce, policy version, expected-state binding, atomic single-use marker. |
| Time-of-check/time-of-use state change | Mutations re-check expected state remotely before action. Deployments verify current release and repository state. |
| Dirty or conflicting deployment | Clean repository requirement, exact 40-character commit, allow-ref reachability, isolated worktree. |
| Failed deployment verification | Atomic activation and automatic prior-release restoration after probe failure. |
| Unsafe rollback | Only recorded releases are eligible; database migrations are never automatically reversed. |
| Audit editing | Hash chain and verification command; external immutable replication recommended. |
| Supply-chain compromise | Pinned dependency versions, audit gate, CodeQL, restricted install scripts, review required for updates. |
| Private data contamination | Generic fixtures only plus tracked-file and full-history secret scanning before release. |

## Explicit non-goals

V1 is not a general remote administration shell, privileged orchestration platform, secrets manager, database migration engine, container exec service, file transfer tool, or public multi-tenant MCP endpoint. Root compromise, kernel compromise, malicious root-owned configuration, and compromise of the human approval workstation are outside the guarantees of the application layer.

## Residual risks

* Hash chaining detects tampering but cannot prevent deletion by an attacker controlling the audit filesystem; ship audit data to immutable storage.
* Trusted configured build steps execute repository code. Use dedicated build hosts or stronger sandboxing for hostile repositories.
* A dedicated deployment account may require write access to configured repositories and release directories. Keep that access isolated from unrelated applications.
* Redaction is defense in depth, not permission to intentionally read arbitrary secret stores.
