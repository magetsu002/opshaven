# Contributing

Keep changes small, typed, and boundary-focused. Every new operation needs:

1. a logical resource contract;
2. strict local policy and schema validation;
3. independent remote validation;
4. fixed executable and argument resolution from configuration;
5. timeout and output bounds;
6. redaction review;
7. audit behavior;
8. focused positive and adversarial tests;
9. documentation;
10. one validated conventional commit.

Never add an arbitrary shell, custom diagnostic command, generic Docker exec, free-form file read, SQL input, dynamic service name, dynamic executable/flags, temporary bypass, or public MCP listener.

Run before submitting:

```bash
npm run check
npm run security
```

Use only generic fixtures. Repository content and Git history must remain free of unrelated private project names, infrastructure, URLs, identifiers, and secrets.
