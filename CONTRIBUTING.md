# Contributing

Thank you for improving OpsHaven.

## Development rules

* Preserve the no-shell and logical-resource architecture.
* Keep policy, transport, dispatcher, operations, approval, redaction, audit, and MCP code separated.
* Validate every new trust-boundary field and reject unknown fields.
* Use fixed executables and argument arrays; never add shell interpolation or a generic command escape hatch.
* Add focused tests and an adversarial regression test for every security defect.
* Use only generic fixtures. Do not commit real hosts, organizations, infrastructure, URLs, credentials, logs, fingerprints, or identifiers.
* Commit coherent validated changes with conventional commit messages.

## Validation

```sh
npm install --ignore-scripts
npm run check
npm run test:security
npm run security:scan
npm run docs:check
npm run test:integration
```

The integration suite requires Docker and an OpenSSH client. Pull requests that change security boundaries, deployment behavior, approval semantics, redaction, or the dispatcher should explain the threat addressed and the fail-closed behavior.

## Review checklist

Confirm no arbitrary command/path/URL input was introduced; no output bounds were weakened; mutations still require exact approval; remote validation remains independent; fixtures are generic; documentation matches behavior; and the full CI matrix passes at the pull-request head.
