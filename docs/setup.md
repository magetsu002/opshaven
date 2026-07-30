# Setup and bootstrap

## Local MCP server

1. Install Node.js 22 or newer and OpenSSH client tools.
2. Run `npm install --ignore-scripts` and `npm run build`.
3. Copy `examples/opshaven.config.json` to a private root-owned location and replace every generic value.
4. Create a dedicated SSH key and a dedicated `known_hosts` file. Record the SHA-256 host-key fingerprint out of band.
5. Load the approval key from a secret manager into the configured environment variable.
6. Validate with `opshaven config validate`, then run `opshaven doctor`.

## VPS dispatcher

Build the project, run `scripts/bootstrap-dispatcher.sh` as root, and then run `scripts/install-dispatcher.sh /absolute/path/dispatcher.config.json logical-host-id`. The installer validates and binds that logical host ID into a root-owned wrapper. Install the generated forced-command wrapper, the `Match User` SSH fragment, and an authorized key containing both `restrict` and the exact dispatcher command.

Generate narrowly scoped sudo rules with:

```sh
node dist/cli.js sudoers render --config /absolute/path/dispatcher.config.json
```

Review the output, install it under `/etc/sudoers.d/`, and validate with `visudo -cf`. Never replace exact commands with wildcards.

## Validation

```sh
scripts/validate.sh
OPSHAVEN_RUN_INTEGRATION=1 scripts/validate.sh
```
