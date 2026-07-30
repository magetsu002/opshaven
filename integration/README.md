# Disposable restricted-SSH integration fixture

This fixture builds a generic Debian-based VPS container with a dedicated `opshaven` account, public-key-only authentication, a forced dispatcher command, disabled forwarding and TTY allocation, a generic Git repository, and a planted environment secret.

Run:

```sh
npm run test:integration
```

The suite proves real pinned-host-key SSH, fixed dispatcher execution, logical-resource inspection, environment-value non-disclosure, shell-escape rejection, host-key mismatch rejection, and local audit-chain verification. It requires Docker, OpenSSH client tools, and Node.js 22 or newer.
