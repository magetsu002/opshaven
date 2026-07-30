# Configuration

OpsHaven uses one strict versioned JSON document. Copy [`examples/opshaven.config.json`](../examples/opshaven.config.json) to an absolute private path and replace only generic values. Unknown keys, duplicate IDs, invalid references, malformed paths, invalid URLs, unsafe refs, and unsupported strategies are rejected.

## Resource types

* `hosts`: SSH endpoint, account, identity, pinned known-hosts file and fingerprint, dispatcher command, firewall provider.
* `applications`: grouping metadata bound to one host.
* `services`: logical ID to exact systemd unit, optional runtime environment file, required environment key names, restart permission.
* `containers`: logical ID to configured container identity.
* `deployments`: trusted repository, release directory, active symlink, state ledger, allowed refs, activation strategy, services, probes, checks, builds, migration-risk policy.
* `proxies`: configured reverse-proxy provider and resource metadata.
* `probes`: fixed loopback/private health URL, expected statuses, timeout.
* `databases`: metadata-only database resources; V1 exposes no SQL execution.
* `monitoring`: configured service groups used to report monitoring evidence.
* `backups`: provider, evidence marker, restore procedure, and freshness threshold.

## Defaults

`defaults.timeoutMs` and `defaults.output` bound operations globally. Individual operations may lower limits; deployment operations use a larger fixed ceiling but remain bounded.

## Audit and approvals

`audit.path` is the local JSONL chain. `approvals.stateDirectory` stores single-use nonce markers. `approvals.ttlSeconds` limits token lifetime. `approvals.keyEnvironmentVariable` names the environment variable holding the approval HMAC key; the value is never stored in configuration.

## Redaction

`secrets.keyNames` lists sensitive key names. `secrets.fingerprints` contains precomputed literal fingerprints that should be replaced wherever encountered. Never put raw secret values in this file.

## Validation

```sh
node dist/cli.js config validate --config /absolute/path/opshaven.config.json
node dist/cli.js doctor --config /absolute/path/opshaven.config.json
```

Keep separate local and VPS copies when paths differ. The VPS copy should contain only resources assigned to the bound logical host ID.
