# V1 release certification

A release tag is created only from the exact commit that passes every required gate.

## Candidate gates

* Fresh checkout and clean dependency installation.
* Format/lint policy, strict typecheck, all tests, and production build.
* Local MCP stdio startup and protocol smoke test.
* Adversarial security tests and repository/history secret scan.
* Dependency audit and CodeQL.
* Disposable real OpenSSH fixture proving forced-command access, host-key pinning, no shell, bounded structured output, no environment values, and valid audit evidence.
* Deployment tests proving non-mutating dry-run, exact commit activation, automatic restoration after failed health verification, and recorded-release rollback.
* Approval tests proving expiry, forgery rejection, argument/expected-state mutation rejection, and single-use replay prevention.
* Audit tests proving modification and deletion detection.
* Documentation link and required-document validation.
* Private-data review of tracked files and Git history.

## Exact-head rule

After any code, dependency, workflow, documentation, or version change, all gates must run again on the new commit. A previous green run does not certify a changed head.

## Tagging

Only after exact-head certification:

1. Set package version to `1.0.0` in a dedicated release commit.
2. Re-run all gates on that commit.
3. Create an annotated `v1.0.0` tag at that exact SHA.
4. Publish release notes containing the commit, gate results, supported tools, security boundaries, and known limitations.

Do not create, move, or reuse the tag when any gate is skipped, unavailable, or inconclusive.
