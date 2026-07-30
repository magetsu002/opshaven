# Remote confinement

OpsHaven validates its remote trust files before processing authenticated requests. The dispatcher artifact, remote configuration, signed capability manifest, operator public key, and response-signing key must be real files at normalized absolute paths. They must not be symlinks, group-writable, world-writable, or owned by the restricted account. The artifact hash must match the operator-signed capability manifest.

The replay and temporary-state directory is owned by the restricted account with mode `0700`. The dispatcher sets a `0077` umask and redirects temporary-file variables into a private directory under that state root. Parent directories are checked for path substitution and unsafe ownership.

## Isolated read-only mode

Install `packaging/opshaven-readonly-force-command` as root-owned mode `0755` and use it as the forced SSH command. It launches the isolated dispatcher through `setpriv` with no-new-privileges, an empty capability set, a reset environment, no shell, and no inherited home directory.

`packaging/systemd/opshaven-readonly-dispatcher@.service` is a socket-activated reference profile for systems that place the dispatcher behind a private Unix socket. It provides a read-only system filesystem, private devices and temporary space, an empty capability set, syscall filtering, and no privilege escalation. Remove `AF_INET` and `AF_INET6` from `RestrictAddressFamilies` when the signed manifest does not allow health probes.

The read-only dispatcher rejects startup when a system Docker socket is present in its execution namespace. Container inspection belongs only to the controlled dispatcher and should use a separately reviewed rootless Docker environment.

## Controlled mode exceptions

Controlled mode may require exactly reviewed release-directory writes, configured health-probe networking, and exact `sudo` rules for named systemd units. `NoNewPrivileges=yes` cannot be used for a process that must execute those setuid `sudo` transitions. This is an explicit exception, not a general privilege grant. Keep the restricted account out of root-equivalent Docker groups and grant no wildcard commands, shells, editors, package managers, arbitrary environment assignment, forwarding, or PTY access.

System-call filtering varies between Linux distributions and systemd releases. Validate the provided profile on the target distribution before adoption. Any required relaxation should be documented, limited to the affected operation, and reflected in the signed capability declaration.
