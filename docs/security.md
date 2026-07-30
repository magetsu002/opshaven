# Security requirements

## Local files

- SSH identity and approval private/HMAC files: owner-only regular files, mode `0600`.
- known-hosts and approval public key: regular non-symlink files.
- configuration: regular non-symlink file with trusted ownership.
- audit and approval directories: private to the local operator.

Generate local approval material with `scripts/bootstrap-local.sh`. Transfer only the Ed25519 public key to the VPS.

## SSH account

Use one dedicated non-root account per trust domain. Install both key-level restrictions and an sshd `Match User` forced command. Do not enable password authentication, PTY, agent forwarding, TCP forwarding, X11 forwarding, tunneling, or a public MCP listener.

Possession of the restricted SSH key alone is insufficient for mutation: the VPS verifies a separate signed approval and consumes its nonce.

## Secrets

Runtime configuration status reads only configured environment-file key names and returns presence booleans. It never returns values. Do not configure secret-bearing probe query strings or credential-bearing URLs. Logs are still untrusted and are redacted twice.

`secretFingerprints` should contain SHA-256 fingerprints of specific planted or high-risk secret values, never the secret values themselves.

## Dependency posture

The runtime has no npm dependencies. TypeScript is a pinned development dependency. CI runs type checking, tests, a production dependency audit, repository/history secret scanning, and a real restricted-SSH integration fixture.

## Reporting

Security reports should describe the affected boundary and reproduction using generic fixtures. Never place real infrastructure identifiers or secret material in an issue.
