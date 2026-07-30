# Setup and MCP onboarding

## 1. Build and validate

```bash
npm install --ignore-scripts --no-audit --no-fund
npm run check
```

## 2. Initialize local protected state

```bash
scripts/bootstrap-local.sh "$HOME/.config/opshaven" "$HOME/.local/state/opshaven"
```

Copy `examples/local.config.json` and replace placeholders with generic logical resource IDs and trusted absolute paths. Add the VPS host key out of band; never use an automatic accept-new policy for production.

```bash
ssh-keyscan -H your-host.example > "$HOME/.config/opshaven/known_hosts.pending"
# Verify the fingerprint through a separate trusted channel, then install it.
```

Run:

```bash
opshaven validate-config --config /absolute/path/local.config.json
opshaven diagnostics --config /absolute/path/local.config.json
```

## 3. Install the remote dispatcher

Copy only the compiled application, validated remote configuration, restricted SSH public key, and approval public key. Use `scripts/bootstrap-remote.sh`, then add exact sudo rules only for configured systemd restart units.

Confirm an attempted SSH command returns a policy denial rather than a shell.

## 4. Configure an MCP client

Generate a client snippet:

```bash
opshaven print-mcp-config --config /absolute/path/local.config.json
```

The MCP server must remain a local stdio child process. Do not expose it through HTTP, a public reverse proxy, or a shared unauthenticated socket.

## 5. Validate safe behavior

Start with read operations. Exercise mutation dry-runs and confirm `changed: false`. Create a human approval only after reviewing the exact plan. Verify the audit chain after testing.
