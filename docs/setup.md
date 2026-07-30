# Setup

This guide connects a local OpsHaven MCP server to a restricted Linux VPS.

## Requirements

You need:

```text
Node.js 22 or newer
SSH access to the VPS
A dedicated non-root VPS account
```

Clone the repository, install dependencies, and verify the build:

```bash
npm install --ignore-scripts --no-audit --no-fund
npm run check
npm run build
```

## Initialize OpsHaven locally

Create the protected configuration, approval, and audit directories:

```bash
scripts/bootstrap-local.sh \
  "$HOME/.config/opshaven" \
  "$HOME/.local/state/opshaven"
```

Copy the example configuration:

```bash
cp examples/local.config.json \
  "$HOME/.config/opshaven/config.json"
```

Edit the copied file with your VPS connection details and logical resource IDs.

OpsHaven requires absolute trusted paths. Resources such as services, deployments, health probes, and log sources must be declared in the configuration before an agent can access them.

## Trust the VPS host key

Collect the host key into a temporary file:

```bash
ssh-keyscan -H your-host.example \
  > "$HOME/.config/opshaven/known_hosts.pending"
```

Verify its fingerprint through a separate trusted channel before installing it:

```bash
mv "$HOME/.config/opshaven/known_hosts.pending" \
  "$HOME/.config/opshaven/known_hosts"
```

Do not use automatic host-key acceptance for production systems.

## Install the VPS dispatcher

Build OpsHaven locally, then copy the required files to the VPS:

```text
compiled dispatcher
remote configuration
restricted SSH public key
approval public key
```

Run the remote bootstrap script on the VPS:

```bash
sudo scripts/bootstrap-remote.sh
```

The script creates the restricted account and installs the forced-command dispatcher.

Add only the sudo permissions required by the configured operations. For example, a systemd service restart should permit only the exact configured unit rather than unrestricted `systemctl` access.

Test the SSH boundary before continuing. An attempted custom command should return a policy denial and must never open a shell.

## Validate the configuration

Run the local validation commands:

```bash
opshaven validate-config \
  --config "$HOME/.config/opshaven/config.json"

opshaven diagnostics \
  --config "$HOME/.config/opshaven/config.json"
```

Resolve every reported error before connecting an MCP client.

## Connect an MCP client

Generate the client configuration:

```bash
opshaven print-mcp-config \
  --config "$HOME/.config/opshaven/config.json"
```

Add the generated entry to your MCP client configuration.

OpsHaven runs as a local stdio process. Do not place it behind HTTP, expose it through a reverse proxy, or bind it to a public socket.

## Test the connection

Begin with read-only operations:

```text
get_host_summary
get_service_status
get_deployed_commit
run_health_probe
```

Confirm the responses refer only to configured resources and do not expose secret values.

Next, test a mutation using dry-run mode. The result should show the resolved operation while reporting:

```json
{
  "changed": false
}
```

Only create an approval after reviewing the exact target and expected change.

Finally, verify the audit log:

```bash
opshaven audit verify \
  --config "$HOME/.config/opshaven/config.json"
```

OpsHaven is ready once read operations succeed, dry-runs make no changes, unauthorized commands are denied, and the audit chain verifies.
