# Operations runbook

## Before use

1. Validate the configuration.
2. Run `opshaven doctor` and resolve every failure.
3. Verify the audit chain.
4. Confirm the host-key fingerprint through an independent channel.
5. Start with read-only inspection and dry-runs.

## Inspection

Use logical IDs only. Host, service, container, proxy, firewall, probe, monitoring, backup, restore, and release tools return structured evidence rather than raw command output. `get_runtime_config_status` returns required-key presence only. `get_redacted_logs` is limited to 1–500 lines and one of `15m`, `1h`, or `24h`.

## Human approval workflow

1. Call a mutation without `approval` or perform its `dryRun` first.
2. Review the resolved target, exact arguments, expected state, policy version, migration warning, expiry, and digest in `details.approvalRequest`.
3. Save only that request to a private file.
4. Sign it from a human-controlled terminal:

```sh
node dist/cli.js approve \
  --config /absolute/path/opshaven.config.json \
  --request /absolute/private/path/request.json
```

5. Retry the identical MCP call with the token before expiry.
6. Verify resulting service/health/release state and the audit chain.

Never approve a request whose target or expected state does not match your independent observation.

## Restart

Run `restart_service` as a dry-run with the expected current active state. A real restart checks that state again, invokes the exact configured unit through narrowly scoped sudo, and verifies the service reaches `active`.

## Incident handling

On host-key mismatch, malformed output, audit failure, unexpected state, or secret-redaction concern: stop mutations, preserve logs and audit evidence, rotate affected credentials, verify the VPS wrapper/config ownership, and investigate through an independent administrator channel. Do not bypass the failed control.

## Routine maintenance

* Re-run diagnostics after key rotation, host rebuild, configuration changes, and dependency upgrades.
* Regenerate and review sudoers after service/deployment changes.
* Test backups and the documented restore procedure independently.
* Prune old release directories only after preserving the recorded state and confirming they are not rollback targets.
