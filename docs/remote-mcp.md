# Secure remote MCP

OpsHaven supports two MCP transports:

- **stdio** is the default. The AI client starts `opshaven-mcp` locally and no network listener exists.
- **Streamable HTTP** is opt-in. An explicit `opshaven serve --transport streamable-http` command starts a localhost listener protected by OAuth/OIDC, exact host and origin rules, bounded sessions where required by the negotiated MCP revision, resource limits, and the signed read-only capability.

Do not put the stdio process behind Supergateway or another generic relay. Such a bridge cannot enforce OpsHaven's authenticated principal, proxy, origin, session, rate-limit, and signed remote-capability boundaries.

## Supported architecture

```text
Hosted MCP client
→ HTTPS tunnel or trusted reverse proxy
→ 127.0.0.1-bound OpsHaven Streamable HTTP server
→ OIDC bearer verification
→ operator-owned subject-to-profile mapping
→ signed read-only capability intersection
→ restricted SSH read-only dispatcher
→ authenticated, minimized, redacted response
→ tamper-evident audit log
```

The OpsHaven listener does not terminate public TLS. Keep it on loopback and expose only `/mcp` through a reviewed HTTPS tunnel or reverse proxy. Direct public binding is unsupported and causes boundary verification to fail.

## Companion configuration

Remote settings live beside the local configuration as:

```text
/absolute/path/config.json.remote.json
```

The file is optional. Absence means remote MCP is disabled. Unknown fields and insecure combinations are rejected.

A reviewed example follows. Replace only the generic example values with values belonging to the operator and identity provider.

```json
{
  "enabled": true,
  "bindHost": "127.0.0.1",
  "port": 43110,
  "path": "/mcp",
  "allowedOrigins": [
    "https://client.example"
  ],
  "allowedHosts": [
    "mcp.example"
  ],
  "trustedProxies": [
    "127.0.0.2"
  ],
  "oauth": {
    "issuer": "https://issuer.example",
    "audience": "opshaven-remote",
    "requiredScopes": [
      "mcp:invoke"
    ],
    "allowedAlgorithms": [
      "EdDSA",
      "RS256"
    ],
    "allowedJwksHosts": [
      "issuer.example"
    ],
    "metadataCacheSeconds": 300,
    "keyCacheSeconds": 300,
    "minimumRefreshSeconds": 10,
    "fetchTimeoutMs": 3000,
    "clockSkewSeconds": 30
  },
  "profiles": [
    {
      "id": "readonly-operator",
      "subjects": [
        "operator-subject-id"
      ],
      "requiredScopes": [
        "opshaven:read"
      ],
      "allowedTools": [
        "get_host_summary",
        "get_service_status",
        "run_health_probe",
        "get_redacted_logs"
      ],
      "allowedResourceIds": [
        "host.main",
        "svc.web",
        "probe.web"
      ],
      "capability": "read-only",
      "sessionLimits": {
        "maximumSessions": 2,
        "lifetimeSeconds": 3600,
        "inactivitySeconds": 300,
        "maximumPendingRequests": 4
      },
      "rateLimits": {
        "windowSeconds": 60,
        "maximumRequests": 30,
        "concurrency": 2
      }
    }
  ],
  "sessions": {
    "maximumGlobal": 16,
    "maximumPerPrincipal": 2,
    "lifetimeSeconds": 3600,
    "inactivitySeconds": 300,
    "maximumPendingPerSession": 4
  },
  "requests": {
    "maximumBodyBytes": 65536,
    "maximumHeaderBytes": 16384,
    "maximumHeaders": 48,
    "maximumJsonDepth": 16,
    "maximumJsonNodes": 2048,
    "timeoutMs": 10000,
    "maximumResponseBytes": 262144,
    "globalConcurrency": 8,
    "perPrincipalConcurrency": 2,
    "maximumQueue": 8
  },
  "rateLimits": {
    "windowSeconds": 60,
    "maximumRequests": 100
  }
}
```

The client never selects a profile. OpsHaven maps the verified issuer and subject to exactly one operator-configured profile, then intersects its tools and resource IDs with the active signed read-only capability manifest.

## OAuth and OIDC provider

Use an external provider that publishes OpenID Provider metadata and a JWKS endpoint over HTTPS.

Configure:

- the exact issuer URL;
- a dedicated audience for OpsHaven;
- required global and profile scopes;
- an explicit signing-algorithm allowlist;
- the exact JWKS host allowlist;
- short bounded metadata and key caches;
- provider fetch and clock-skew limits.

OpsHaven validates the token signature, issuer, audience, expiry, not-before time, issue time, scopes, and subject mapping. Tokens in query strings are rejected. Provider discovery or key failure is fail-closed. Raw tokens are not written to logs or audit records.

Rotate provider keys and revoke access through the provider. Remove a subject from every profile when access ends. Keep token lifetimes short and review provider audit logs. Restart OpsHaven after changing the companion configuration so the new profile and boundary state is loaded atomically.

## HTTPS tunnel or reverse proxy

Forward only the configured MCP path to the loopback listener. Do not proxy SSH, dispatcher, Podman, Docker, filesystem, health, diagnostics, or administrative endpoints.

For a direct tunnel connection, configure the tunnel hostname in `allowedHosts` and the hosted client's HTTPS origin in `allowedOrigins`.

For a reverse proxy:

- list the proxy's exact source address in `trustedProxies`;
- replace incoming forwarding headers rather than appending to them;
- send one `X-Forwarded-For` value;
- send one `X-Forwarded-Host` value;
- send `X-Forwarded-Proto: https`;
- do not send the generic `Forwarded` header;
- reject requests to every path except `/mcp`;
- set conservative connection, request-body, and idle timeouts at the proxy too.

OpsHaven rejects forwarding headers from untrusted addresses and rejects duplicated, comma-joined, incomplete, or ambiguous forwarding data. It does not emit wildcard CORS or credentialed cross-origin headers.

## Start and verify

Validate configuration and the installed SSH boundary:

```bash
opshaven validate-config --config /absolute/path/config.json
opshaven diagnostics --config /absolute/path/config.json
opshaven verify-boundary --mode read-only --config /absolute/path/config.json
opshaven trust-report --mode read-only --config /absolute/path/config.json
```

Print the credential-free local endpoint:

```bash
opshaven print-remote-mcp-url --config /absolute/path/config.json
```

Start the listener explicitly:

```bash
opshaven serve \
  --transport streamable-http \
  --config /absolute/path/config.json
```

The process handles `SIGINT` and `SIGTERM`, stops accepting requests, clears in-memory sessions and queues, aborts active remote work, and closes the listener. Verify audit-chain integrity after testing:

```bash
opshaven verify-audit --config /absolute/path/config.json
```

Audit actors identify the transport, hashed authenticated principal, profile, session when applicable, tool, resource, and outcome. Access tokens are never included.

## Hosted client examples

In ChatGPT or Claude, use the product's interface for adding a custom remote MCP server when that interface is available to the operator's account and workspace:

```text
Server URL: https://mcp.example/mcp
Authentication: OAuth through the configured external provider
```

Do not paste a bearer token into a URL, prompt, configuration field intended for query parameters, or repository file. The hosted client must reach the HTTPS proxy or tunnel, not the localhost URL printed by OpsHaven.

These examples describe the endpoint shape only. Availability and setup controls vary by client product and account configuration and must be verified in the client's current documentation.

## Disposable rootless Podman test

Use only synthetic resources and disposable credentials:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build
integration/remote-mcp-podman/run.sh
```

The test target starts a rootless container with a local test issuer and synthetic read-only operation service, verifies initialization and one tool call through the native HTTP transport, runs adversarial denials, and removes generated keys, tokens, sessions, containers, and listener state on exit.

Never point the disposable workflow at production resources or reuse production OAuth, SSH, capability, or response-signing keys.

## Unsupported exposure patterns

The following are outside the reviewed boundary:

- binding the listener to a public interface;
- directly exposing the listener without HTTPS;
- wildcard origins or hosts;
- trusting forwarding headers from arbitrary addresses;
- static unauthenticated tokens or an unauthenticated fallback;
- mutation tools in remote profiles;
- a generic stdio-to-HTTP relay;
- proxying diagnostics, configuration, filesystem, container-engine, SSH, or dispatcher endpoints;
- embedding credentials in URLs.
