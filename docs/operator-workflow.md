# Operator workflow

This guide describes the parts an operator runs, the material each side stores, and the checks that authorize an operation. It avoids relying on product-specific shorthand.

## Executables

`opshaven` is the human command-line interface. Use it for setup, diagnostics, boundary verification, authorization reports, endpoint handoff, and controlled approvals.

`opshaven-mcp` is the stdio MCP protocol server. An MCP client launches it and exchanges JSON-RPC messages through standard input and output. It is not an interactive terminal command.

The remote dispatcher is installed under a dedicated restricted account. It is invoked only by the forced SSH command and does not provide a shell.

## What runs locally

The operator machine runs:

- the `opshaven` CLI;
- the `opshaven-mcp` protocol process for local MCP clients;
- local policy validation;
- request signing and response verification;
- approval creation for controlled operations;
- audit-chain verification;
- remote setup, rollback, uninstall, and boundary-verification commands.

The local policy maps logical resource IDs to reviewed hosts, services, probes, deployments, and other allowed targets. AI clients never supply executable paths, SSH identities, service names, or arbitrary shell text.

## What runs remotely

The VPS contains:

- a dedicated non-root `opshaven` account;
- a forced-command wrapper;
- the isolated read-only dispatcher, or the separately reviewed controlled dispatcher for local-only mutation workflows;
- root-owned policy and signed authorization artifacts;
- replay state and audit state;
- a response-signing private key generated on the VPS.

The remote account has no interactive shell. The read-only installation has no sudo rule, deployment write access, system Docker socket access, or mutation handler.

## Keys that stay local

The following private material stays on the operator machine:

- administrator SSH private key used only for installation lifecycle work;
- restricted-account SSH private key used by the local client;
- capability-authorization signing private key;
- approval signing private key and approval replay secret;
- release-signing private material;
- OAuth client secrets, when a chosen identity-provider flow requires them.

OpsHaven does not upload these private keys as installation artifacts. File permissions are validated before use.

## Material uploaded to the VPS

Remote setup uploads only the material required for independent enforcement:

- the reviewed dispatcher runtime and forced-command wrapper;
- the remote policy containing logical resource mappings;
- the restricted SSH public key;
- operator public verification keys;
- signed capability authorization;
- the signed build capability declaration and binding;
- installation metadata required for rollback and uninstall.

The VPS generates its response-signing private key locally. Only the corresponding public key is copied back to the operator machine.

## Authorization flow

An operation is permitted only when all applicable checks agree:

1. The MCP tool and logical resource exist in the local policy.
2. The signed capability authorization permits the operation, resource, limits, policy version, and dispatcher identity.
3. The local process signs a bounded request containing a nonce and expiry.
4. Restricted SSH invokes only the forced dispatcher.
5. The dispatcher independently validates the request, policy, signatures, artifact hashes, time bounds, and replay state.
6. Controlled mutations also require a separate short-lived approval for the exact operation and arguments.
7. The VPS signs the bounded response.
8. The local process verifies the response signature, request binding, dispatcher identity, and result hash.
9. The operation is appended to the tamper-evident audit chain.

Failure at any step blocks the operation. No fallback shell or unsigned execution path is provided.

## Operator terminology

The operator interface uses these terms:

- **Authorization artifacts**: signed capability authorization, public verification keys, declaration binding, and related policy material.
- **Capability authorization**: the signed operations, resources, limits, policy version, expiry, and dispatcher identity accepted by both sides.
- **Deployment attestation**: evidence that the installed runtime, policy, wrapper, and recorded source identity match the reviewed installation.
- **Runtime attestation**: verification that the executing dispatcher artifact matches the authorized hash.
- **Boundary verification**: active checks proving shell denial, command denial, signature enforcement, replay resistance, host-key pinning, and audit integrity.
- **Signed policy artifacts**: the root-owned policy, capability authorization, declarations, bindings, and public keys used by the dispatcher.

Some internal source files, JSON fields, and the legacy `opshaven trust-report` command retain older names to avoid an unnecessary compatibility migration. Operators should use `opshaven authorization-report`; both commands currently produce the same report.

## Diagnostics

Run:

```bash
opshaven doctor --config /absolute/path/to/local.config.json
```

The report separates:

- local operator environment;
- remote deployment state;
- authorization artifacts;
- endpoint readiness;
- security boundary status.

`READY` means the configured local files passed validation, authenticated remote inspection succeeded, endpoint policy passed, and boundary verification completed successfully. `BLOCKED` means at least one required check failed. The command never prints private key contents or secret values.

Use JSON only for automation:

```bash
opshaven doctor \
  --json \
  --config /absolute/path/to/local.config.json
```

## MCP exposure

Local stdio is the default. Configure the MCP client to run:

```text
opshaven-mcp --config /absolute/path/to/local.config.json
```

No network listener starts in this mode.

Remote MCP is opt-in. The reviewed deployment binds the Streamable HTTP server to loopback and places an HTTPS tunnel or explicitly configured reverse proxy in front of it. Before a tool is exposed, the request must pass OIDC bearer verification, exact origin and host checks, explicit proxy handling, profile mapping, rate and concurrency limits, and signed read-only capability intersection.

Remote profiles cannot expose restart, deployment, rollback, or approval tools. Direct public binding, wildcard origins, wildcard hosts, unauthenticated fallback, and generic stdio-to-HTTP relays remain outside the reviewed boundary.

## Normal sequence

```bash
opshaven setup remote --dry-run --config /absolute/path/to/remote-setup.json
opshaven setup remote --tui --config /absolute/path/to/remote-setup.json
opshaven doctor --config /absolute/path/to/local.config.json
opshaven boundary verify \
  --config /absolute/path/to/local.config.json \
  --setup-config /absolute/path/to/remote-setup.json
opshaven authorization-report \
  --mode read-only \
  --config /absolute/path/to/local.config.json
```

Do not expose an MCP endpoint until diagnostics and boundary verification both pass on the installed deployment.
