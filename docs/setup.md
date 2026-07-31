# Setup

This guide connects OpsHaven to a restricted Linux VPS. Start with a disposable server that contains no production secrets or customer data. The automated setup workflow installs only the isolated read-only dispatcher.

## Requirements

The operator machine needs:

- Linux or macOS;
- Node.js 22 or newer;
- a clean checkout at the exact reviewed commit;
- OpenSSH client tools, `ssh-keygen`, and `scp` at their standard absolute paths;
- an administrator SSH identity and separately verified host-key fingerprint;
- an Ed25519 restricted-account SSH key;
- an Ed25519 operator signing key pair kept only on the operator machine.

The VPS needs a supported Ubuntu or Debian release, Python 3, OpenSSH, OpenSSL, `setpriv`, at least 128 MiB of free space, and Node.js 22 or newer at one reviewed absolute path.

Validate the repository before setup:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm run security
```

## Prepare local state

Create protected configuration and audit directories:

```bash
scripts/bootstrap-local.sh \
  "$HOME/.config/opshaven" \
  "$HOME/.local/state/opshaven"
```

Create the local policy from `examples/local.config.json`. Create a second remote dispatcher policy beside it using the suffix `.dispatcher.json`.

```text
$HOME/.config/opshaven/config.json
$HOME/.config/opshaven/config.json.dispatcher.json
```

Both policies must use the same policy version, limits, logical resource IDs, and resource kinds. The local policy uses local SSH, approval, audit, and response-verification paths. The remote policy uses root-owned `/etc/opshaven` trust paths and `/var/lib/opshaven` state paths.

Generate operator and restricted SSH keys locally. Never upload the administrator SSH private key or operator signing private key as installation material.

## Pin the VPS host key

Collect the host key into a pending file:

```bash
ssh-keyscan -t ed25519 your-host.example \
  > "$HOME/.config/opshaven/known_hosts.pending"
```

Display its SHA-256 fingerprint:

```bash
ssh-keygen -lf \
  "$HOME/.config/opshaven/known_hosts.pending" \
  -E sha256
```

Compare it through a separate trusted channel. Only then install the file:

```bash
mv "$HOME/.config/opshaven/known_hosts.pending" \
  "$HOME/.config/opshaven/known_hosts"
```

OpsHaven does not silently use trust on first use.

## Create the setup configuration

Create an owner-only JSON file such as `$HOME/.config/opshaven/remote-setup.json`:

```json
{
  "version": 1,
  "policyConfigPath": "/home/operator/.config/opshaven/config.json",
  "expectedSourceSha": "0123456789abcdef0123456789abcdef01234567",
  "target": {
    "host": "vps.example.test",
    "port": 22,
    "adminUser": "ubuntu",
    "knownHostsFile": "/home/operator/.config/opshaven/known_hosts",
    "identityFile": "/home/operator/.ssh/vps-admin",
    "expectedHostKeySha256": "SHA256:replace-with-separately-verified-value",
    "privilege": "sudo-noninteractive"
  },
  "local": {
    "runtimeRoot": "/absolute/opshaven/dist-readonly",
    "dispatcherPath": "/absolute/opshaven/dist-readonly/src/remote/read-only-dispatcher.js",
    "wrapperTemplatePath": "/absolute/opshaven/packaging/opshaven-readonly-force-command",
    "capabilityDeclarationPath": "/absolute/opshaven/security/capability-declaration.json",
    "operatorPrivateKeyFile": "/home/operator/.config/opshaven/operator-private.pem",
    "operatorPublicKeyFile": "/home/operator/.config/opshaven/operator-public.pem",
    "restrictedAuthorizedKeyFile": "/home/operator/.ssh/opshaven-readonly.pub"
  },
  "remote": {
    "account": "opshaven",
    "runtimeRoot": "/usr/lib/opshaven",
    "configPath": "/etc/opshaven/config.json",
    "wrapperPath": "/usr/local/bin/opshaven-readonly-force-command",
    "stateDirectory": "/var/lib/opshaven",
    "receiptPath": "/var/lib/opshaven/setup-receipt.json",
    "nodeCandidates": [
      "/usr/bin/node",
      "/usr/local/bin/node"
    ]
  },
  "trust": {
    "expiresInSeconds": 86400
  }
}
```

The remote account and installation paths are fixed by the reviewed schema. Setup rejects unknown fields, changed authority paths, path traversal, duplicate Node candidates, unsupported privilege modes, and non-Ed25519 restricted keys.

Protect the file:

```bash
chmod 600 "$HOME/.config/opshaven/remote-setup.json"
```

## Preview and install

Build the exact read-only runtime:

```bash
npm run build
```

Preview every local and VPS action without mutation:

```bash
opshaven setup remote \
  --dry-run \
  --config "$HOME/.config/opshaven/remote-setup.json"
```

Run the guided terminal interface:

```bash
opshaven setup remote \
  --tui \
  --config "$HOME/.config/opshaven/remote-setup.json"
```

For CI or other reviewed automation, approval remains explicit:

```bash
opshaven setup remote \
  --non-interactive \
  --approve \
  --config "$HOME/.config/opshaven/remote-setup.json"
```

The engine performs these stages:

1. verifies the exact local source head, local files, key correspondence, pinned host fingerprint, SSH connectivity, remote platform, resolved Node executable, disk space, privilege, and existing installation state;
2. creates or validates the locked `opshaven` account with no sudo or privileged-group membership;
3. installs the complete hashed read-only runtime tree, forced-command wrapper, policy, and restricted `authorized_keys` atomically;
4. generates and verifies the read-only capability and declaration binding locally;
5. uploads only public operator material and signed trust documents;
6. generates the response-signing private key on the VPS and downloads only its public key;
7. proves shell denial, host-key pinning, capability and declaration validity, authenticated read-only execution, replay and mutation resistance, malformed-input denial, and audit integrity;
8. writes matching local and remote receipts only after certification succeeds.

A repeat run is idempotent. Unchanged runtime and installation files are retained rather than replaced.

## Diagnose and certify

Inspect local policy and trust files:

```bash
opshaven doctor \
  --config "$HOME/.config/opshaven/config.json"
```

Run the complete installed boundary certification:

```bash
opshaven boundary verify \
  --config "$HOME/.config/opshaven/config.json" \
  --setup-config "$HOME/.config/opshaven/remote-setup.json"
```

A failed assertion returns nonzero. Endpoint handoff remains blocked until the protected remote receipt contains a matching successful certification.

Review the active authority separately:

```bash
opshaven trust-report \
  --mode read-only \
  --config "$HOME/.config/opshaven/config.json"
```

## Roll back or uninstall

Rollback restores files recorded in the protected setup receipt and removes newly created recorded files. It does not search for or remove unrelated server content.

```bash
opshaven setup remote \
  --rollback \
  --approve \
  --config "$HOME/.config/opshaven/remote-setup.json"
```

Uninstall removes only fixed OpsHaven paths and the exact forced-command key entry. It preserves unrelated `authorized_keys` entries, unrelated files, users, services, and SSH configuration.

```bash
opshaven uninstall remote \
  --approve \
  --config "$HOME/.config/opshaven/remote-setup.json"
```

Both commands emit a machine-readable receipt. Omit `--approve` to confirm that destructive execution remains blocked.

## Prepare endpoint handoff

Create a reviewed remote MCP companion configuration as described in [Secure remote MCP](remote-mcp.md). It must keep `bindHost` on loopback, include exact Host and Origin allowlists, use only loopback trusted proxies, and define OIDC issuer, audience, JWKS hosts, scopes, operator profiles, sessions, replay controls, rate limits, concurrency, request bounds, and response bounds.

Prepare generic HTTPS proxy or tunnel instructions:

```bash
opshaven endpoint expose \
  --setup-config "$HOME/.config/opshaven/remote-setup.json" \
  --endpoint-config "$HOME/.config/opshaven/remote-endpoint.json" \
  --external-url "https://mcp.example.test/mcp"
```

After the external HTTPS route exists, prove that anonymous access remains denied by OIDC:

```bash
opshaven endpoint expose \
  --setup-config "$HOME/.config/opshaven/remote-setup.json" \
  --endpoint-config "$HOME/.config/opshaven/remote-endpoint.json" \
  --external-url "https://mcp.example.test/mcp" \
  --verify-external
```

Inspect current handoff state:

```bash
opshaven endpoint status \
  --setup-config "$HOME/.config/opshaven/remote-setup.json"
```

The command refuses public OpsHaven binding, credential-bearing URLs, mismatched paths, permissive proxy state, missing OIDC assumptions, wildcard CORS evidence, and endpoints that accept anonymous MCP requests.

## Troubleshooting

### `setpriv: apply bounding set: Operation not permitted`

The current wrapper must not contain `--bounding-set=-all`. The restricted SSH user cannot change its capability bounding set after `sshd` drops privileges. Rebuild from the exact reviewed source and rerun setup. The wrapper still enforces `no_new_privs`, clears inheritable and ambient capabilities, resets the environment, and denies `SSH_ORIGINAL_COMMAND` before reset.

### Missing `/usr/bin/node`

Add the real absolute Node.js 22+ executable to `remote.nodeCandidates`. Preflight resolves and verifies the candidate before mutation, and the installed wrapper records that exact path. Setup fails closed when no candidate works.

### Incomplete runtime dependency tree

Run `npm run build` from the exact expected head. Setup requires every compiled read-only dependency and hashes each file through a no-follow descriptor before staging. It refuses partial copies and symbolic links.

### Dispatcher is not executable

Do not chmod files manually. Rerun setup. The atomic installer applies executable mode only to the reviewed read-only dispatcher entry and verifies it after replacement.

### Host-key fingerprint mismatch

Stop. Recollect the host key and verify its SHA-256 fingerprint through a separate trusted channel. Do not change the expected value merely to make preflight pass.

### Operator public key mismatch

Regenerate or select the correct Ed25519 public key for the configured private key. Setup verifies key correspondence before signing or upload.

### Expired or changed trust files

Rerun setup from the exact expected head to generate a new capability and declaration binding. Changed dispatcher hashes, stale signatures, expired trust, and incorrectly scoped authority are rejected locally and remotely.

### Boundary certification fails

Run `opshaven doctor`, preserve the setup and audit receipts, and inspect the failed assertion. Do not expose `/mcp` or weaken the failed check.

## Local stdio and controlled mode

The default `opshaven-mcp` entrypoint remains local stdio and starts no network listener. Controlled restart, deployment, and rollback operations remain separate from automated read-only remote setup. They still require exact local approvals, reviewed filesystem writes, and narrow sudo rules. See [the sudoers example](sudoers.example) and [Remote confinement](confinement.md).

Verify the audit chain after testing:

```bash
opshaven verify-audit \
  --config "$HOME/.config/opshaven/config.json"
```

Treat failed host-key checks, trust verification, authenticated responses, rollback receipts, endpoint authentication checks, or audit verification as security incidents. Preserve evidence rather than rewriting it.
