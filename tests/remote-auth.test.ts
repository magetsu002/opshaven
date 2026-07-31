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
const privateKey = keyPair.privateKey.export({ type: "pkcs8", format: "pem" });
const publicJwk = { ...keyPair.publicKey.export({ format: "jwk" }), kid: "fixture-key", alg: "EdDSA", use: "sig", key_ops: ["verify"] };

const base = parseConfig({
  version: 1,
  policyVersion: "v1",
  limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
  audit: { path: "/var/lib/opshaven/audit.jsonl" },
  approvals: { directory: "/var/lib/opshaven/approvals", secretFile: "/var/lib/opshaven/secret", signingPrivateKeyFile: "/var/lib/opshaven/private.pem", verificationPublicKeyFile: "/etc/opshaven/public.pem", remoteUsedDirectory: "/var/lib/opshaven/remote-used", defaultTtlSeconds: 300 },
  secretFingerprints: [],
  resources: [{ id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id", connectTimeoutMs: 5000 }],
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
    allowedAlgorithms: ["EdDSA"],
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
  calls: string[] = [];
  available = true;
  async fetchJson(url: string): Promise<unknown> {
    this.calls.push(url);
    if (!this.available) throw new Error("unavailable");
    if (url.endsWith("/.well-known/openid-configuration")) return { issuer, jwks_uri: `${issuer}/jwks` };
    if (url.endsWith("/jwks")) return { keys: [publicJwk] };
    throw new Error("unexpected URL");
  }
}

function encoded(value: unknown): string { return Buffer.from(JSON.stringify(value), "utf8").toString("base64url"); }
function token(overrides: Record<string, unknown> = {}, headerOverrides: Record<string, unknown> = {}): string {
  const header = encoded({ alg: "EdDSA", kid: "fixture-key", typ: "at+jwt", ...headerOverrides });
  const payload = encoded({ iss: issuer, sub: "subject-1", aud: audience, exp: Math.floor(now / 1000) + 300, nbf: Math.floor(now / 1000) - 10, iat: Math.floor(now / 1000) - 10, scope: "mcp:invoke opshaven:read", ...overrides });
  const signature = sign(null, Buffer.from(`${header}.${payload}`, "utf8"), privateKey).toString("base64url");
  return `${header}.${payload}.${signature}`;
}
function identity(bearer?: string, target = "/mcp") {
  return { authorization: bearer === undefined ? undefined : `Bearer ${bearer}`, remoteAddress: "127.0.0.1", requestTarget: target, headers: {} };
}

async function rejected(verifier: OidcPrincipalVerifier, bearer?: string, target = "/mcp"): Promise<void> {
  await assert.rejects(verifier.verify(identity(bearer, target)), (error: unknown) => error instanceof Error && error.message === "Remote authentication failed." && !error.message.includes(bearer ?? "never"));
}

test("OIDC verifier binds an authenticated subject to its operator profile", async () => {
  const fetcher = new FixtureFetcher();
  const verifier = new OidcPrincipalVerifier(remote, fetcher, () => now);
  const principal = await verifier.verify(identity(token()));
  assert.equal(Object.isFrozen(principal), true);
  assert.equal(principal.transport, "streamable-http");
  assert.equal(principal.profileId, "readonly-operator");
  assert.equal(principal.allowedTools?.has("get_host_summary"), true);
  assert.equal(principal.allowedTools?.has("restart_service"), false);
  assert.equal(principal.allowedResources?.has("host.main"), true);
  assert.match(principal.id, /^[a-f0-9]{64}$/);
  await verifier.verify(identity(token()));
  assert.equal(fetcher.calls.filter((url) => url.endsWith("/.well-known/openid-configuration")).length, 1);
  assert.equal(fetcher.calls.filter((url) => url.endsWith("/jwks")).length, 1);
});

test("OIDC verifier rejects malformed, inactive, mismatched, and insufficient tokens", async () => {
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now));
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), "not-a-jwt");
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), token({ exp: Math.floor(now / 1000) - 30 }));
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), token({ nbf: Math.floor(now / 1000) + 30 }));
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), token({ iss: "https://wrong.example.test" }));
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), token({ aud: "wrong-audience" }));
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), token({ scope: "mcp:invoke" }));
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), token({ sub: "unknown-subject" }));
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), token(), "/mcp?access_token=forbidden");
  await rejected(new OidcPrincipalVerifier(remote, new FixtureFetcher(), () => now), token({}, { alg: "none" }));
});

test("OIDC verification fails closed when provider metadata is unavailable", async () => {
  const fetcher = new FixtureFetcher();
  fetcher.available = false;
  await rejected(new OidcPrincipalVerifier(remote, fetcher, () => now), token());
});

test("remote configuration rejects mutation capabilities and duplicate subject mappings", () => {
  const candidate = JSON.parse(JSON.stringify(remote)) as any;
  candidate.profiles[0].allowedTools.push("restart_service");
  assert.throws(() => parseRemoteMcpConfig(candidate, base));
  const duplicate = JSON.parse(JSON.stringify(remote)) as any;
  duplicate.profiles.push({ ...duplicate.profiles[0], id: "second-profile" });
  assert.throws(() => parseRemoteMcpConfig(duplicate, base));
});
