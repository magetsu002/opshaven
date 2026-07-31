import { constants as cryptoConstants, createPublicKey, verify } from "node:crypto";
import { sha256 } from "../canonical.js";
import type { McpPrincipal } from "../mcp.js";
import type { EnabledRemoteMcpConfig, RemoteProfile } from "./config.js";
import { RemoteAuthenticationError, type HttpRequestIdentity, type PrincipalVerifier } from "./http.js";

interface JwtHeader { readonly alg: string; readonly kid: string; readonly typ?: string }
interface JwtClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string | readonly string[];
  readonly exp: number;
  readonly nbf?: number;
  readonly iat?: number;
  readonly scope?: string;
  readonly scp?: readonly string[];
}
interface ProviderMetadata { readonly issuer: string; readonly jwks_uri: string }
interface PublicJwk extends Record<string, unknown> { readonly kid: string; readonly kty: string; readonly alg?: string; readonly use?: string; readonly key_ops?: readonly string[] }
interface CachedMetadata { readonly value: ProviderMetadata; readonly expiresAt: number }
interface CachedKeys { readonly values: readonly PublicJwk[]; readonly expiresAt: number }
export interface RemoteJsonFetcher { fetchJson(url: string, maximumBytes: number, timeoutMs: number): Promise<unknown> }

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const PRIVATE_JWK_FIELDS = new Set(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);

function plain(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function fail(status: 401 | 403 = 401): never { throw new RemoteAuthenticationError(status, "Remote authentication failed."); }
function canonicalDecode(encoded: string, maximumBytes: number): Uint8Array {
  if (!BASE64URL.test(encoded) || encoded.length > Math.ceil(maximumBytes * 4 / 3) + 8) fail();
  let decoded: Uint8Array;
  try { decoded = Buffer.from(encoded, "base64url"); }
  catch { fail(); }
  if (decoded.length > maximumBytes || Buffer.from(decoded).toString("base64url") !== encoded) fail();
  return decoded;
}
function jsonPart(encoded: string, maximumBytes: number): unknown {
  try { return JSON.parse(Buffer.from(canonicalDecode(encoded, maximumBytes)).toString("utf8")) as unknown; }
  catch { fail(); }
}
function numberDate(value: unknown): value is number { return typeof value === "number" && Number.isInteger(value) && value > 0 && value < 100000000000; }
function parseHeader(value: unknown, allowed: ReadonlySet<string>): JwtHeader {
  if (!plain(value) || typeof value.alg !== "string" || !allowed.has(value.alg) || typeof value.kid !== "string" || value.kid.length < 1 || value.kid.length > 256) fail();
  if (value.alg === "none" || value.jku !== undefined || value.x5u !== undefined || value.jwk !== undefined || value.crit !== undefined) fail();
  if (value.typ !== undefined && value.typ !== "JWT" && value.typ !== "at+jwt") fail();
  return { alg: value.alg, kid: value.kid, ...(typeof value.typ === "string" ? { typ: value.typ } : {}) };
}
function parseClaims(value: unknown): JwtClaims {
  if (!plain(value) || typeof value.iss !== "string" || typeof value.sub !== "string" || value.sub.length < 1 || value.sub.length > 256 || !(typeof value.aud === "string" || (Array.isArray(value.aud) && value.aud.length > 0 && value.aud.length <= 16 && value.aud.every((item) => typeof item === "string"))) || !numberDate(value.exp)) fail();
  if (value.nbf !== undefined && !numberDate(value.nbf)) fail();
  if (value.iat !== undefined && !numberDate(value.iat)) fail();
  if (value.scope !== undefined && (typeof value.scope !== "string" || value.scope.length > 4096)) fail();
  if (value.scp !== undefined && (!Array.isArray(value.scp) || value.scp.length > 128 || !value.scp.every((item) => typeof item === "string" && item.length > 0 && item.length <= 128))) fail();
  return value as unknown as JwtClaims;
}
function tokenScopes(claims: JwtClaims): ReadonlySet<string> {
  const values = new Set<string>();
  if (typeof claims.scope === "string") for (const item of claims.scope.split(/\s+/).filter(Boolean)) values.add(item);
  if (Array.isArray(claims.scp)) for (const item of claims.scp) values.add(item);
  return values;
}
function audienceIncludes(audience: JwtClaims["aud"], expected: string): boolean { return typeof audience === "string" ? audience === expected : audience.includes(expected); }
function profileFor(config: EnabledRemoteMcpConfig, subject: string): RemoteProfile | undefined { return config.profiles.find((profile) => profile.subjects.includes(subject)); }
function keyMatches(header: JwtHeader, key: PublicJwk): boolean {
  if (key.kid !== header.kid || (key.alg !== undefined && key.alg !== header.alg) || (key.use !== undefined && key.use !== "sig") || (key.key_ops !== undefined && !key.key_ops.includes("verify"))) return false;
  if (Object.keys(key).some((name) => PRIVATE_JWK_FIELDS.has(name))) return false;
  if ((header.alg === "RS256" || header.alg === "PS256") && key.kty !== "RSA") return false;
  if (header.alg === "ES256" && (key.kty !== "EC" || key.crv !== "P-256")) return false;
  if (header.alg === "EdDSA" && (key.kty !== "OKP" || key.crv !== "Ed25519")) return false;
  return true;
}
function attemptVerification(operation: () => boolean): boolean {
  try { return operation(); }
  catch { return false; }
}
function verifySignature(header: JwtHeader, key: PublicJwk, signingInput: string, signature: Uint8Array): boolean {
  let publicKey: unknown;
  try { publicKey = createPublicKey({ key, format: "jwk" }); }
  catch { return false; }
  const data = Buffer.from(signingInput, "utf8");
  const eddsa = attemptVerification(() => verify(null, data, publicKey, signature));
  const es256 = attemptVerification(() => verify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature));
  const ps256 = attemptVerification(() => verify("sha256", data, { key: publicKey, padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature));
  const rs256 = attemptVerification(() => verify("RSA-SHA256", data, publicKey, signature));
  switch (header.alg) {
    case "EdDSA": return eddsa;
    case "ES256": return es256;
    case "PS256": return ps256;
    case "RS256": return rs256;
    default: return false;
  }
}
function readonlySet(values: readonly string[]): ReadonlySet<string> { return new Set(values); }
function safeTargetHasToken(target: string): boolean {
  if (target.length > 4096) return true;
  let parsed: URL;
  try { parsed = new URL(target, "http://localhost"); }
  catch { return true; }
  return ["access_token", "token", "authorization"].some((name) => parsed.searchParams.has(name));
}

async function readResponseBounded(response: any, maximumBytes: number): Promise<string> {
  const declared = Number(response.headers?.get?.("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maximumBytes) throw new Error("Provider response exceeded its bound.");
  const reader = response.body?.getReader?.();
  if (!reader) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > maximumBytes) throw new Error("Provider response exceeded its bound.");
    return Buffer.from(bytes).toString("utf8");
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    const chunk = result.value as Uint8Array;
    total += chunk.length;
    if (total > maximumBytes) { await reader.cancel(); throw new Error("Provider response exceeded its bound."); }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export class DefaultRemoteJsonFetcher implements RemoteJsonFetcher {
  async fetchJson(url: string, maximumBytes: number, timeoutMs: number): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { method: "GET", headers: { accept: "application/json" }, redirect: "error", signal: controller.signal });
      if (!response.ok || !response.headers.get("content-type")?.toLowerCase().includes("application/json")) throw new Error("Provider metadata request failed.");
      return JSON.parse(await readResponseBounded(response, maximumBytes)) as unknown;
    } finally { clearTimeout(timer); }
  }
}

export class OidcPrincipalVerifier implements PrincipalVerifier {
  private metadata: CachedMetadata | undefined;
  private keys: CachedKeys | undefined;
  private metadataFetch: Promise<ProviderMetadata> | undefined;
  private keyFetch: Promise<readonly PublicJwk[]> | undefined;
  private lastKeyRefresh = 0;
  constructor(private readonly config: EnabledRemoteMcpConfig, private readonly fetcher: RemoteJsonFetcher = new DefaultRemoteJsonFetcher(), private readonly clock: () => number = Date.now) {}

  private metadataUrl(): string { return `${this.config.oauth.issuer}/.well-known/openid-configuration`; }
  private parseMetadata(value: unknown): ProviderMetadata {
    if (!plain(value) || value.issuer !== this.config.oauth.issuer || typeof value.jwks_uri !== "string" || value.jwks_uri.length > 2048) fail();
    let parsed: URL;
    try { parsed = new URL(value.jwks_uri); }
    catch { fail(); }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || !this.config.oauth.allowedJwksHosts.includes(parsed.hostname)) fail();
    return Object.freeze({ issuer: value.issuer, jwks_uri: parsed.toString() });
  }
  private parseKeys(value: unknown): readonly PublicJwk[] {
    if (!plain(value) || !Array.isArray(value.keys) || value.keys.length < 1 || value.keys.length > 64) fail();
    const keys = value.keys.map((item) => {
      if (!plain(item) || typeof item.kid !== "string" || item.kid.length < 1 || item.kid.length > 256 || typeof item.kty !== "string") fail();
      return Object.freeze({ ...item }) as PublicJwk;
    });
    if (new Set(keys.map((key) => key.kid)).size !== keys.length) fail();
    return Object.freeze(keys);
  }
  private async getMetadata(): Promise<ProviderMetadata> {
    const now = this.clock();
    if (this.metadata && this.metadata.expiresAt > now) return this.metadata.value;
    if (!this.metadataFetch) this.metadataFetch = this.fetcher.fetchJson(this.metadataUrl(), 262144, this.config.oauth.fetchTimeoutMs).then((value) => this.parseMetadata(value));
    try {
      const value = await this.metadataFetch;
      this.metadata = { value, expiresAt: now + this.config.oauth.metadataCacheSeconds * 1000 };
      return value;
    } catch { fail(); }
    finally { this.metadataFetch = undefined; }
  }
  private async getKeys(force: boolean): Promise<readonly PublicJwk[]> {
    const now = this.clock();
    if (!force && this.keys && this.keys.expiresAt > now) return this.keys.values;
    if (force && now - this.lastKeyRefresh < this.config.oauth.minimumRefreshSeconds * 1000) return this.keys?.values ?? fail();
    if (!this.keyFetch) {
      this.lastKeyRefresh = now;
      this.keyFetch = this.getMetadata().then((metadata) => this.fetcher.fetchJson(metadata.jwks_uri, 1048576, this.config.oauth.fetchTimeoutMs)).then((value) => this.parseKeys(value));
    }
    try {
      const values = await this.keyFetch;
      this.keys = { values, expiresAt: now + this.config.oauth.keyCacheSeconds * 1000 };
      return values;
    } catch { fail(); }
    finally { this.keyFetch = undefined; }
  }

  async verify(identity: HttpRequestIdentity): Promise<McpPrincipal> {
    if (safeTargetHasToken(identity.requestTarget)) fail();
    const authorization = identity.authorization;
    if (!authorization || authorization.length > 16384) fail();
    const match = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(authorization);
    if (!match?.[1]) fail();
    const token = match[1];
    const parts = token.split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) fail();
    const allowed = new Set<string>(this.config.oauth.allowedAlgorithms);
    const header = parseHeader(jsonPart(parts[0], 8192), allowed);
    const claims = parseClaims(jsonPart(parts[1], 65536));
    const signature = canonicalDecode(parts[2], 1024);
    let keys = await this.getKeys(false);
    let key = keys.find((candidate) => keyMatches(header, candidate));
    if (!key) {
      keys = await this.getKeys(true);
      key = keys.find((candidate) => keyMatches(header, candidate));
    }
    if (!key || !verifySignature(header, key, `${parts[0]}.${parts[1]}`, signature)) fail();
    const nowSeconds = Math.floor(this.clock() / 1000);
    const skew = this.config.oauth.clockSkewSeconds;
    if (claims.iss !== this.config.oauth.issuer || !audienceIncludes(claims.aud, this.config.oauth.audience) || claims.exp <= nowSeconds - skew || (claims.nbf !== undefined && claims.nbf > nowSeconds + skew) || (claims.iat !== undefined && claims.iat > nowSeconds + skew)) fail();
    const scopes = tokenScopes(claims);
    if (this.config.oauth.requiredScopes.some((scope) => !scopes.has(scope))) fail(403);
    const profile = profileFor(this.config, claims.sub);
    if (!profile || profile.requiredScopes.some((scope) => !scopes.has(scope))) fail(403);
    const principalId = sha256({ issuer: claims.iss, subject: claims.sub });
    return Object.freeze({
      id: principalId,
      transport: "streamable-http" as const,
      profileId: profile.id,
      allowedTools: readonlySet(profile.allowedTools),
      allowedResources: readonlySet(profile.allowedResourceIds),
    });
  }
}
