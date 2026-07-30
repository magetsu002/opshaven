# Architecture

## Components

### Local MCP server

The server runs over stdio and is intended to be launched by a local MCP client. It does not bind a TCP port. It exposes a fixed tool catalogue, strict JSON schemas, and stable success/error envelopes.

### Configuration and logical resources

A single strict JSON configuration describes hosts, applications, services, containers, deployments, reverse proxies, probes, databases, monitoring groups, and backups. Agent input can select only these logical IDs. Unknown fields and broken references are rejected during configuration load.

### Policy and approval

The policy engine converts tool input into a `ResolvedOperation`. This object contains the trusted host, target, normalized arguments, expected state, timeout, output bounds, policy version, dry-run flag, and mutation status. Mutation approval signs a canonical digest of that resolved object and is expiring, single-use, and atomically consumed.

### Restricted SSH transport

The transport invokes fixed OpenSSH binaries with argument arrays and `shell: false`. It requires a dedicated identity file, a dedicated known-hosts file, and an out-of-band SHA-256 host-key fingerprint. PTY, forwarding, tunnels, agent use, and host-key fallback are disabled. Input and output are bounded.

### Forced-command dispatcher

The remote account is pinned to one root-owned wrapper by both `sshd_config` and `authorized_keys`. The dispatcher accepts no command-line arguments and exactly one bounded JSON request on stdin. It reloads strict root-owned configuration and independently validates the operation before choosing an immutable handler.

### Operation handlers

Handlers are small modules grouped by inspection, networking, logs, recovery, mutations, and deployments. Subprocesses use fixed executables and arrays. Units, repository paths, release paths, URLs, and build steps originate only from validated configuration.

### Redaction and envelopes

Remote handlers avoid reading secret values where possible. Results are structured, bounded, binary-rejected, and redacted remotely. The local service validates the remote envelope and performs a second redaction pass before returning it to the MCP client.

### Audit chain

The local append-only JSONL audit stores a hash of each canonical record and the prior record hash. Verification detects edits, deletion, insertion, reordering, truncation that leaves an invalid terminal chain, and malformed records. External immutable storage is recommended for stronger deletion resistance.

## Data flow

1. The MCP adapter rejects unknown methods and malformed JSON-RPC.
2. The policy engine resolves logical IDs and rejects unknown input.
3. A read operation is audited as allowed; a mutation without approval returns an exact approval request.
4. The approval verifier checks signature, expiry, policy version, target, arguments, expected state, and nonce replay state.
5. The SSH transport verifies the pinned host key and invokes only the configured dispatcher command.
6. The dispatcher parses and re-resolves the operation independently.
7. A fixed handler executes bounded commands or trusted release steps.
8. The dispatcher returns one strict structured envelope.
9. The local service validates, redacts, audits the result digest, and returns a stable MCP result.

## Trust boundaries

* **MCP input:** untrusted agent-controlled JSON.
* **Local configuration:** trusted only after strict parsing; protect it as an administrative file.
* **Approval terminal:** human-controlled trust boundary; approval keys must not be exposed to the agent.
* **SSH network:** hostile; host identity is pinned and all channel features are disabled.
* **Remote account:** constrained but not treated as sufficient alone; the dispatcher repeats validation.
* **VPS configuration and wrapper:** root-owned trusted computing base.
* **Command output:** untrusted, potentially secret-bearing, malformed, or excessive.
* **Audit storage:** integrity protected by chaining, but availability and deletion resistance depend on filesystem controls and external retention.
