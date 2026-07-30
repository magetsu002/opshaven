# Security

OpsHaven is designed to give AI agents useful VPS access without giving them a shell.

This guide covers the main security assumptions for running it safely.

## Local machine

Keep the local OpsHaven files private:

* SSH private keys and approval signing material should be owned by the local user and use mode `0600`.
* Configuration, known-hosts, and approval public keys should be regular files, not symlinks.
* Audit and approval directories should only be accessible to the operator.

Generate the local approval keys with:

```bash
scripts/bootstrap-local.sh
```

Only copy the generated public approval key to the VPS.

## Restricted SSH account

Use a dedicated non-root SSH account for OpsHaven.

The account should have:

* public-key authentication only
* a forced command
* no interactive shell
* no PTY
* no agent, TCP, X11, or tunnel forwarding
* narrowly scoped sudo access where required

Use both SSH key restrictions and an `sshd` `Match User` rule. This keeps the account restricted even if one layer is misconfigured.

The SSH key alone cannot approve changes. Mutating operations also require a separate signed approval that the VPS verifies and consumes once.

## Secrets and logs

OpsHaven should avoid reading secrets whenever possible.

Runtime configuration checks return only whether configured variables are present. They never return variable values.

Health probes should use credential-free URLs. Do not place passwords, API keys, or tokens in probe paths or query strings.

Logs are treated as untrusted input and are redacted before and after crossing the SSH boundary.

For especially sensitive values, configure their SHA-256 hashes under `secretFingerprints`. Store fingerprints only, never the original values.

## Dependencies and validation

OpsHaven has no production npm dependencies.

Before submitting or releasing changes, run:

```bash
npm run check
npm run security
```

CI also verifies:

* type safety and tests
* production dependency audit
* repository and Git-history secret scanning
* the restricted SSH integration environment

## Reporting a security issue

Please avoid opening a public issue for a vulnerability that could expose secrets, bypass approval, escape the restricted account, or alter unrelated services.

Include:

* the affected boundary
* the expected and observed behavior
* a minimal reproduction using generic fixtures
* the relevant OpsHaven version or commit

Do not include real credentials, hostnames, IP addresses, customer information, or private infrastructure details.
