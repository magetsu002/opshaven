# Security controls

## Invariants

OpsHaven never accepts agent-provided commands, flags, service units, filesystem paths, SQL, deployment scripts, or arbitrary URLs. Every executable and argument source is either a constant or strict trusted configuration. Unknown operations, resources, fields, states, and remote envelope fields fail closed.

## Files and ownership

Keep local configuration, SSH private keys, known-hosts files, approval state, and audit files outside the repository. Configuration paths must be absolute regular files, not symlinks. On the VPS, the dispatcher code, wrapper, configuration, SSH policy, and sudoers entries must be root-owned and not writable by the `opshaven` account.

## SSH restrictions

Use one dedicated key and one dedicated account per security boundary when practical. Verify host fingerprints out of band. Never set `StrictHostKeyChecking=no`, reuse an unrestricted administration key, permit password authentication, or remove either forced-command layer.

## Approvals

The approval key must remain in a human-controlled secret store and must not be exposed in the agent-visible environment. An approval covers one exact canonical operation and expires quickly. Any change to the target, arguments, expected state, policy version, expiry, or digest invalidates it. Dry-runs do not require approval and must not mutate state.

## Secrets and output

Runtime configuration tools report key presence and safe metadata only. Health probes discard response bodies. Log retrieval is constrained to configured units, fixed time windows, and bounded lines. Credentials, authorization headers, cookies, credential-bearing URLs, JWT-like values, keys, tokens, and configured fingerprints are redacted remotely and locally.

## Deployment safety

Deployments accept only exact commits reachable from configured allowed refs. The dispatcher rejects dirty repositories, stages isolated worktrees, runs only configured executable/argument arrays, activates through an atomic symlink, checks configured health probes, and restores the previous release on failed verification. Database migration reversal is never inferred or automated.

## Audit handling

Run `opshaven audit verify --config ...` regularly and before/after sensitive maintenance. Protect the audit path with filesystem permissions and forward records or chain checkpoints to immutable storage. Treat an invalid chain as an incident.

## Vulnerability reporting

Do not open a public issue containing a vulnerability, exploit path, key, token, host, log excerpt, or private configuration. Use GitHub private vulnerability reporting when enabled. Include affected version/commit, impact, minimal generic reproduction, and suggested mitigation. Do not test against systems without authorization.
