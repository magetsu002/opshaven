# Contributing to OpsHaven

Thanks for helping make AI-assisted VPS operations safer and easier to use.

OpsHaven welcomes documentation improvements, focused bug fixes, new tests, safer defaults, and carefully bounded operational support. You do not need to be a security expert to contribute. Clear questions and small improvements are valuable.

## Start small

OpsHaven sits on a security boundary, so changes should be focused and easy to review. A small fix with strong tests is usually more useful than a broad rewrite.

Good first contributions include:

- clearer setup instructions and examples;
- friendlier errors and diagnostics;
- stronger input validation;
- redaction and data-minimization tests;
- compatibility fixes for a supported Linux environment;
- improvements to `verify-boundary` or `trust-report` output;
- focused coverage for a known operational failure mode.

For larger changes or new operations, open an issue first so the use case, authority required, and security impact can be discussed before implementation.

## Preserve the operator boundary

OpsHaven intentionally does not provide arbitrary shell access, unrestricted file reads, free-form SQL, generic container execution, public MCP listeners, silent capability expansion, or automatic updates.

A new feature should not require users to trust the project author with their server. Operators must continue to own their keys, resource mappings, capabilities, installation, and updates.

Read-only additions must remain compatible with the isolated read-only dispatcher. Controlled operations must declare and justify every required write, executable, network path, sudo rule, and output field.

## Adding or changing an operation

Define an operation from end to end:

```text
logical resource
→ local schema validation
→ policy and capability decision
→ authenticated restricted-SSH request
→ independent remote validation
→ fixed handler
→ minimized and bounded result
→ authenticated response
→ local verification
→ audit record
```

The AI client must never choose the executable, flags, service name, filesystem path, or raw command. Those details come only from validated operator configuration.

Every operation should include focused success tests and adversarial coverage for invalid input, unsafe paths, replay, mutation, oversized output, timeouts, malicious data, and boundary bypasses where relevant.

## Development

Install dependencies:

```bash
npm ci --ignore-scripts --no-audit --no-fund
```

Run the repository checks:

```bash
npm run release:check
npm run security
scripts/check-reproducible-build.sh
```

Changes that affect restricted SSH, confinement, authenticated protocol handling, deployment, or approvals should also run:

```bash
integration/disposable-vps/run.sh
```

Keep commits small and use clear conventional commit messages, for example:

```text
feat: add configured timer inspection
fix: reject symlinked deployment paths
docs: clarify read-only setup
test: cover replayed response rejection
```

## Pull requests

A helpful pull request explains:

- what changed;
- why it is useful;
- which trust boundary it touches;
- whether declared capabilities changed;
- how the behavior was tested.

Avoid unrelated cleanup or broad refactoring in the same pull request.

Use generic examples and fixtures only. Never include real credentials, private infrastructure, internal URLs, customer names, hostnames, IP addresses, or unrelated project identifiers.

## Need help?

Open an issue with the use case, expected behavior, and the boundary you are unsure about. Early questions are welcome, especially before a large security-sensitive change is written.
