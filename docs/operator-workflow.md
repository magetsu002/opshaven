# Operator workflow

OpsHaven keeps setup details behind the human CLI. A normal operator does not create policy JSON, capability files, declaration bindings, dispatcher hashes, or remote installation manifests by hand.

## Executables

`opshaven` is the human command-line interface. Use it for initialization, remote setup, diagnostics, boundary verification, reports, endpoint handoff, and controlled approvals.

`opshaven-mcp` is the stdio MCP protocol server launched by an MCP client. It is not an interactive terminal command.

## First run

Build the reviewed checkout, then initialize the local operator environment:

```bash
npm run build
opshaven init
```

In an interactive terminal, OpsHaven asks only for deployment facts an operator can reasonably provide:

- remote hostname or IP address;
- SSH port and administrator user;
- administrator SSH private-key path;
- pinned known-hosts file;
- separately verified SHA-256 host-key fingerprint.

OpsHaven creates the protected local directories, authorization keys, restricted SSH key, local policy, remote dispatcher policy, and setup state automatically. Normal output does not reveal their internal filenames.

For reviewed non-interactive automation, the same information can be supplied as operator-facing flags:

```bash
opshaven init \
  --non-interactive \
  --host vps.example.test \
  --admin-user ubuntu \
  --admin-identity "$HOME/.ssh/vps-admin" \
  --known-hosts "$HOME/.ssh/known_hosts" \
  --host-key-sha256 "SHA256:verified-value" \
  --privilege sudo-noninteractive
```

If `opshaven init` runs without remote details in a non-interactive environment, it still prepares local keys and state. `opshaven doctor` then reports `LOCAL_INITIALIZED`, and `opshaven setup remote` explains that initialization must be completed.

## Install the remote runtime

Preview the plan:

```bash
opshaven setup remote --dry-run
```

Run the guided terminal workflow:

```bash
opshaven setup remote --tui
```

For reviewed automation, mutation approval remains explicit:

```bash
opshaven setup remote --non-interactive --approve
```

The CLI automatically locates the state created by `opshaven init`. Existing installations may continue passing `--config <setup-path>` explicitly.

## Check current state

Run:

```bash
opshaven doctor
```

The normal report answers four questions:

```text
Current state:
LOCAL_INITIALIZED

Completed:
✓ Operator keys
✓ Local configuration

Blocked:
✗ Remote deployment not configured

Next action:
opshaven setup remote
```

Possible states are:

- `NOT_INITIALIZED`: run `opshaven init`;
- `LOCAL_INITIALIZED`: local state exists; run `opshaven setup remote`;
- `REMOTE_CONFIGURED`: setup exists but the installed deployment is not ready; rerun setup;
- `READY`: local state, remote deployment, authorization, and boundary checks passed;
- `BLOCKED`: local state needs repair; rerun initialization.

Use `opshaven doctor --debug` only when troubleshooting. Debug output includes lower-level validation details but still sanitizes protected paths and never prints secret or private-key contents.

## Verify the installed boundary

After setup succeeds:

```bash
opshaven boundary verify
```

The CLI automatically locates both local policy and remote setup state. Boundary verification still proves shell denial, arbitrary-command denial, host-key pinning, signed authorization, replay resistance, response verification, read-only enforcement, and audit integrity.

## Normal sequence

```bash
npm run build
opshaven init
opshaven setup remote --dry-run
opshaven setup remote --tui
opshaven doctor
opshaven boundary verify
opshaven authorization-report --mode read-only
```

Rollback and uninstall use the same generated setup state:

```bash
opshaven setup remote --rollback --approve
opshaven uninstall remote --approve
```

## What remains local

The administrator SSH private key, restricted SSH private key, authorization signing private key, approval secret, release-signing material, and optional OAuth client secrets remain on the operator machine. OpsHaven validates file type and permissions before using them.

## What is installed remotely

Remote setup installs only what the VPS needs to enforce the boundary independently:

- a locked non-root `opshaven` account;
- a forced-command wrapper;
- the isolated read-only dispatcher;
- root-owned policy and public verification material;
- signed authorization data;
- replay and audit state;
- a response-signing private key generated on the VPS.

The remote account has no interactive shell. The read-only installation has no sudo rule, deployment write access, system Docker socket access, or mutation handler.

## Authorization flow

An operation succeeds only when all applicable checks agree:

1. the requested tool and logical resource are allowed;
2. signed capability authorization permits the exact operation and limits;
3. the local process signs a bounded request with a nonce and expiry;
4. restricted SSH invokes only the forced dispatcher;
5. the dispatcher independently verifies policy, signatures, hashes, time bounds, and replay state;
6. controlled mutations also require a separate one-time approval;
7. the VPS signs the bounded response;
8. the local process verifies the response and request binding;
9. the operation is appended to the tamper-evident audit chain.

Failure at any step blocks the operation. No fallback shell or unsigned execution path is provided.

## MCP exposure

Local stdio is the default. Configure the MCP client to run:

```text
opshaven-mcp --config <generated local configuration path>
```

Use `opshaven print-mcp-config` to obtain the generated client configuration without locating internal files manually.

Remote MCP remains opt-in. It binds to loopback and requires an HTTPS tunnel or explicitly configured reverse proxy, OIDC verification, exact Host and Origin checks, profile mapping, rate limits, request bounds, and signed read-only capability intersection. Remote profiles cannot expose restart, deployment, rollback, or approval tools.

Do not expose an MCP endpoint until `opshaven doctor` reports `READY` and `opshaven boundary verify` passes.
