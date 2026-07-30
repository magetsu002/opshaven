# V1 release certification

A `v1.0.0` tag is permitted only at one exact commit where all items pass:

- clean checkout and clean working tree;
- locked clean dependency installation with `npm ci`;
- format validation, lint, strict typecheck, unit/adversarial tests, and build;
- package metadata, built entrypoint, and documentation validation;
- security and relevant Git-history scan;
- MCP server initialization and tool listing;
- unknown tool/resource fail-closed behavior;
- real Docker, systemd, and restricted-SSH disposable VPS fixture;
- attempted shell denial;
- pinned host-key success and changed-host-key failure;
- environment values and planted secrets absent from outputs/errors;
- timeout, line, byte, and binary-output enforcement;
- approval mutation, expiry, state drift, and replay rejection;
- restart approval requirement;
- deploy dry-run no-change evidence;
- exact-commit deployment and configured service activation;
- health-probe verification and failed-health prior-activation restoration;
- recorded rollback restoration;
- complete lifecycle audit-chain verification;
- dependency audit at the configured severity;
- CodeQL analysis;
- exact-head GitHub CI and Security success.

Run local certification from a clean checkout:

```bash
npm run certify
```

The script intentionally refuses to create a tag. Review its evidence and the exact-head GitHub checks, place the certified tree on `main`, confirm post-merge checks, and only then create the annotated `v1.0.0` tag and GitHub release.
