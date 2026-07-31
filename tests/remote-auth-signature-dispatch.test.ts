import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { parseConfig } from "../src/config.js";
import { OidcPrincipalVerifier, type RemoteJsonFetcher } from "../src/remote-mcp/auth.js";
import { parseRemoteMcpConfig, type EnabledRemoteMcpConfig } from "../src/remote-mcp/config.js";

const issuer = "https://issuer.example.test";
const audience = "opshaven-remote";
const now = Date.parse("2026-07-31T00:00:00.000Z");
const keyPair = generateKeyPairSync("ed25519");
const publicJwk = {
  ...keyPair.publicKey.export({ format: "jwk" }),
  kid: "dispatch-regression-key",
  alg: "EdDSA",
  use: "sig",
  key_ops: ["verify"],
};

const base = parseConfig({
  version: 1,
  policyVersion: "v1",
  limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
  audit: { path: "/var/lib/opshaven/audit.jsonl" },
  approvals: {
    directory: "/var/lib/opshaven/approvals",
    secretFile: "/var/lib/opshaven/secret",
    signingPrivateKeyFile: "/var/lib/opshaven/private.pem",
    verificationPublicKeyFile: "/etc/opshaven/public.pem",
    remoteUsedDirectory: "/var/lib/opshaven/remote-used",
    defaultTtlSeconds: 300,
  },
  secretFingerprints: [],
  resources: [{
    id: "host.main",
    kind: "host",
    address: "host.internal",
    port: 22,
    user: "opshaven",
    knownHostsFile: "/etc/opshaven/known_hosts",
    identityFile: "/etc/opshaven/id",
    connectTimeoutMs: 5000,
  }],
});

const remote = parseRemoteMcpConfig({
  enabled: true,
  bindHost: "127.0.0.1",
  port: 43110,
  path: "/mcp",
  allowedOrigins: ["https://chat.example.test"],
  allowedHosts: ["mcp.example.test"],
  trustedProxies: [],
  oauth: {
    issuer,
    audience,
    requiredScopes: ["mcp:invoke"],
    allowedAlgorithms: ["EdDSA", "RS256"],
    allowedJwksHosts: ["issuer.example.test"],
    metadataCacheSeconds: 300,
    keyCacheSeconds: 300,
    minimumRefreshSeconds: 10,
    fetchTimeoutMs: 2000,
    clockSkewSeconds: 5,
  },
  profiles: [{
    id: "readonly-operator",
    subjects: ["subject-1"],
    requiredScopes: ["opshaven:read"],
    allowedTools: ["get_host_summary"],
    allowedResourceIds: ["host.main"],
    capability: "read-only",
    sessionLimits: { maximumSessions: 2, lifetimeSeconds: 3600, inactivitySeconds: 300, maximumPendingRequests: 4 },
    rateLimits: { windowSeconds: 60, maximumRequests: 30, concurrency: 2 },
  }],
  sessions: { maximumGlobal: 16, maximumPerPrincipal: 2, lifetimeSeconds: 3600, inactivitySeconds: 300, maximumPendingPerSession: 4 },
  requests: { maximumBodyBytes: 65536, maximumHeaderBytes: 16384, maximumHeaders: 48, maximumJsonDepth: 16, maximumJsonNodes: 2048, timeoutMs: 10000, maximumResponseBytes: 262144, globalConcurrency: 8, perPrincipalConcurrency: 2, maximumQueue: 8 },
  rateLimits: { windowSeconds: 60, maximumRequests: 100 },
}, base) as EnabledRemoteMcpConfig;

class FixtureFetcher implements RemoteJsonFetcher {
  async fetchJson(url: string): Promise<unknown> {
    if (url.endsWith("/.well-known/openid-configuration")) return { issuer, jwks_uri: `${issuer}/jwks` };
    if (url.endsWith("/jwks")) return { keys: [publicJwk] };
    throw new Error("unexpected URL");
  }
}

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function bearer(algorithm: "EdDSA" | "RS256"): string {
  const header = encoded({ alg: algorithm, kid: "dispatch-regression-key", typ: "at+jwt" });
  const payload = encoded({
    iss: issuer,
    sub: "subject-1",
    aud: audience,
    exp: Math.floor(now / 1000) + 300,
    scope: "mcp:invoke opshaven:read",
  });
  const signature = sign(null, Buffer.from(`${header}.${payload}`, "utf8"), keyPair.privateKey).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

function identity(token: string) {
  return {
    authorization: `Bearer ${token}`,
    remoteAddress: "127.0.0.1",
    requestTarget: "/mcp",
    headers: {},
  };
}

test("OIDC algorithm selection cannot bypass mandatory signature verification", async () => {
  const verifier = new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now);
  const principal = await verifier.verify(identity(bearer("EdDSA")));
  assert.equal(principal.profileId, "readonly-operator");

  await assert.rejects(
    verifier.verify(identity(bearer("RS256"))),
    /Remote authentication failed\./,
  );

  const valid = bearer("EdDSA");
  const parts = valid.split(".");
  assert.equal(parts.length, 3);
  const tampered = `${parts[0]}.${parts[1]}.${Buffer.alloc(64).toString("base64url")}`;
  await assert.rejects(
    verifier.verify(identity(tampered)),
    /Remote authentication failed\./,
  );
});
