# MCP client onboarding

OpsHaven uses local stdio transport only by default. Point the MCP client at the built server and an absolute configuration path:

```json
{
  "mcpServers": {
    "opshaven": {
      "command": "node",
      "args": [
        "/absolute/path/opshaven/dist/index.js",
        "--config",
        "/absolute/private/path/opshaven.config.json"
      ],
      "env": {
        "OPSHAVEN_APPROVAL_KEY": "load-this-from-the-client-secret-store"
      }
    }
  }
}
```

The server writes only JSON-RPC messages to stdout and diagnostics to stderr. Tool arguments contain logical resource IDs, never commands or filesystem paths.

Mutation flow:

1. Call the mutation without `approval`.
2. Save the returned `details.approvalRequest` as a private JSON file.
3. Run `opshaven approve --config ... --request ...` in a human-controlled terminal.
4. Retry the identical tool call with the returned token in `approval` before expiry.

Changing the target, arguments, expected state, policy version, expiry, or token invalidates approval. Tokens are single use.
