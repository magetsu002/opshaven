# Operations guide

## Remote account installation

Build the project, install the complete `dist/src` tree under a root-owned directory, place a small root-owned dispatcher wrapper in `/usr/local/bin`, and run `scripts/bootstrap-remote.sh` with:

```text
public SSH key
compiled dispatcher wrapper
validated remote configuration
approval public key
```

The script does not add broad sudo access.

## Narrow systemd sudo example

Create one reviewed line per configured unit. Keep executable paths and arguments exact:

```sudoers
Defaults:opshaven !requiretty
opshaven ALL=(root) NOPASSWD: /usr/bin/systemctl restart example.service
```

Do not allow wildcards, `systemctl *`, editors, shells, package managers, arbitrary environment assignment, or unrestricted `sudo`. Read-only `systemctl show` normally does not require sudo.

## Containers

Use rootless Docker owned by the restricted account. Do not add the account to a root-equivalent system Docker socket group. Each container name and Compose deployment is configured; no generic `docker exec` exists.

## Logs

`get_redacted_logs` is bounded to at most 500 requested lines and the configured global byte/line limits. Treat redaction as defense-in-depth, not permission to store secrets in logs.

## Approvals

A human runs one of:

```bash
opshaven approve-restart --config /path/config.json --resource svc.example
opshaven approve-deploy --config /path/config.json --resource dep.example --commit <exact-sha> --expected-current <exact-sha>
opshaven approve-rollback --config /path/config.json --resource dep.example --release <recorded-release-id>
```

Review the operation, exact target, expected state, digest, and expiry before placing the token into one MCP call. A failed, expired, replayed, state-drifted, or argument-mutated approval must be replaced with a new review.

## Deployment and rollback

Deployment accepts only exact full commit IDs under configured refs. It refuses dirty state and expected-current mismatches. Trusted build/check steps come only from configuration. Failed health verification restores the previous activation. Rollback accepts only releases in the append-only release ledger and verifies the recorded commit.

Database migration reversal is never automatic. Investigate migration compatibility before deployment or rollback when `migrationPolicy` is `manual`.

## Audit

```bash
opshaven verify-audit --config /path/config.json
```

A failed chain verification is a security incident. Preserve the file and surrounding host evidence; do not rewrite it.
