# V1 release certification

A `v1.0.0` tag is permitted only at one exact commit where all items pass:

- clean checkout and clean working tree;
- clean npm install;
- lint, strict typecheck, unit/adversarial tests, and build;
- security and Git-history scan;
- MCP server initialization and tool listing;
- unknown tool/resource fail-closed behavior;
- real restricted-SSH disposable VPS fixture;
- attempted shell denial;
- pinned host-key success and changed-host-key failure;
- environment values and planted secrets absent from outputs/errors;
- timeout, line, byte, and binary-output enforcement;
- approval mutation, expiry, state drift, and replay rejection;
- restart approval requirement;
- deploy dry-run no-change evidence;
- exact-commit deployment and failed-health prior-activation restoration;
- recorded rollback restoration;
- audit modification detection;
- exact-head GitHub CI success.

Run local certification from a clean checkout:

```bash
npm run certify
```

The script intentionally refuses to create a tag. Review its evidence and the exact-head GitHub checks before creating `v1.0.0` manually.
