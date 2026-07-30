# Contributing to OpsHaven

Thanks for taking the time to improve OpsHaven.

OpsHaven sits on a security boundary, so the best contributions are usually small, focused, and easy to reason about. A clear fix with strong tests is more valuable than a large rewrite.

## Before you start

For larger changes, open an issue first so the design and security impact can be discussed before implementation.

Good contributions include:

* clearer setup and documentation
* stronger validation
* safer error handling
* better redaction
* focused test coverage
* support for a well-defined operational action

OpsHaven intentionally does not provide arbitrary shell access, unrestricted file reads, free-form SQL, generic container execution, or public network access. New features should preserve that boundary.

## Adding or changing an operation

An operation should be defined from end to end:

```text
logical resource
→ local validation
→ policy decision
→ restricted SSH request
→ remote validation
→ fixed handler
→ bounded result
→ redaction
→ audit record
```

The agent should never choose the executable, flags, service name, or filesystem path. Those details must come from validated configuration.

Every operation should include focused success tests and adversarial tests for invalid input, unsafe paths, oversized output, timeouts, and boundary bypasses where relevant.

## Development

Install dependencies:

```bash
npm ci --ignore-scripts --no-audit --no-fund
```

Run the standard checks:

```bash
npm run check
npm run security
```

Keep commits small and use clear conventional commit messages, for example:

```text
feat: add configured timer inspection
fix: reject symlinked deployment paths
docs: clarify restricted SSH setup
```

## Pull requests

A good pull request explains:

* what changed
* why it is needed
* which security boundary it touches
* how it was tested

Avoid unrelated cleanup or broad refactoring in the same pull request.

Use generic examples and fixtures only. Do not include private infrastructure, credentials, internal URLs, customer names, or unrelated project identifiers.

## Need help?

Open an issue with the use case, expected behavior, and the boundary you are unsure about. Security questions are welcome early, before a large implementation is written.
