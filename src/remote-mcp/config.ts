import type { OpsHavenConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { readOptionalRegularTextFile } from "../safe-fs.js";

export const REMOTE_READ_ONLY_TOOLS = new Set([
  "get_host_summary",
  "get_deployed_commit",
  "get_service_status",
  "get_container_status",
  "get_runtime_config_status",
  "get_reverse_proxy_summary",
  "get_firewall_summary",
  "run_health_probe",
  "get_redacted_logs",
  "get_monitoring_status",
  "get_backup_status",
  "get_restore_readiness",
]);

export interface RemoteProfile {
  readonly id: string;
  readonly subjects: readonly string[];
  readonly requiredScopes: readonly string[];
  readonly allowedTools: readonly string[];
  readonly allowedResourceIds: readonly string[];
  readonly capability: "read-only";
  readonly sessionLimits: {
    readonly maximumSessions: number;
    readonly lifetimeSeconds: number;
    readonly inactivitySeconds: number;
    readonly maximumPendingRequests: number;
  };
  readonly rateLimits: {
    readonly windowSeconds: number;
    readonly maximumRequests: number;
    readonly concurrency: number;
  };
}

export interface EnabledRemoteMcpConfig {
  readonly enabled: true;
  readonly bindHost: string;
  readonly port: number;
  readonly path: string;
  readonly allowedOrigins: readonly string[];
  readonly allowedHosts: readonly string[];
  readonly trustedProxies: readonly string[];
  readonly oauth: {
    readonly issuer: string;
    readonly audience: string;
    readonly requiredScopes: readonly string[];
    readonly allowedAlgorithms: readonly ("RS256" | "PS256" | "ES256" | "EdDSA")[];
    readonly allowedJwksHosts: readonly string[];
    readonly metadataCacheSeconds: number;
    readonly keyCacheSeconds: number;
    readonly minimumRefreshSeconds: number;
    readonly fetchTimeoutMs: number;
    readonly clockSkewSeconds: number;
  };
  readonly profiles: readonly RemoteProfile[];
  readonly sessions: {
    readonly maximumGlobal: number;
    readonly maximumPerPrincipal: number;
    readonly lifetimeSeconds: number;
    readonly inactivitySeconds: number;
    readonly maximumPendingPerSession: number;
  };
  readonly requests: {
    readonly maximumBodyBytes: number;
    readonly maximumHeaderBytes: number;
    readonly maximumHeaders: number;
    readonly maximumJsonDepth: number;
    readonly maximumJsonNodes: number;
    readonly timeoutMs: number;
    readonly maximumResponseBytes: number;
    readonly globalConcurrency: number;
    readonly perPrincipalConcurrency: number;
    readonly maximumQueue: number;
  };
  readonly rateLimits: { readonly windowSeconds: number; readonly maximumRequests: number };
}
export type RemoteMcpConfig = { readonly enabled: false } | EnabledRemoteMcpConfig;

const ID = /^[A-Za-z0-9._-]{1,64}$/;
const SUBJECT = /^[^\s\u0000-\u001f\u007f]{1,256}$/;
const SCOPE = /^[A-Za-z0-9._:\/-]{1,128}$/;
const HOST = /^(?:localhost|\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?$/;
const ADDRESS = /^(?:localhost|[A-Za-z0-9.-]+|[0-9A-Fa-f:]+)$/;

function plain(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function exact(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  if (Object.keys(value).some((key) => !allowed.has(key)) || keys.some((key) => !(key in value))) throw new OpsHavenError("CONFIG_INVALID", `${label} has an incompatible schema.`);
}
function integer(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) throw new OpsHavenError("CONFIG_INVALID", `${label} is outside its reviewed bounds.`);
  return value as number;
}
function strings(value: unknown, maximum: number, pattern: RegExp, label: string, allowEmpty = false): string[] {
  if (!Array.isArray(value) || value.length > maximum || (!allowEmpty && value.length === 0)) throw new OpsHavenError("CONFIG_INVALID", `${label} must be a bounded array.`);
  const result = value.map((item) => {
    if (typeof item !== "string" || !pattern.test(item)) throw new OpsHavenError("CONFIG_INVALID", `${label} contains an invalid value.`);
    return item;
  });
  if (new Set(result).size !== result.length) throw new OpsHavenError("CONFIG_INVALID", `${label} must not contain duplicates.`);
  return result;
}
function httpsUrl(value: unknown, label: string): URL {
  if (typeof value !== "string" || value.length > 2048) throw new OpsHavenError("CONFIG_INVALID", `${label} must be an HTTPS URL.`);
  let parsed: URL;
  try { parsed = new URL(value); }
  catch { throw new OpsHavenError("CONFIG_INVALID", `${label} must be an HTTPS URL.`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.hostname.length === 0) throw new OpsHavenError("CONFIG_INVALID", `${label} must be an HTTPS URL without credentials, query, or fragment.`);
  return parsed;
}
function origin(value: unknown, label: string): string {
  const parsed = httpsUrl(value, label);
  if (parsed.pathname !== "/") throw new OpsHavenError("CONFIG_INVALID", `${label} must be an origin without a path.`);
  return parsed.origin;
}
function limits(value: unknown, label: string): Record<string, unknown> {
  if (!plain(value)) throw new OpsHavenError("CONFIG_INVALID", `${label} is malformed.`);
  return value;
}

function parseProfile(value: unknown, config: OpsHavenConfig): RemoteProfile {
  if (!plain(value)) throw new OpsHavenError("CONFIG_INVALID", "Remote profile is malformed.");
  exact(value, ["id", "subjects", "requiredScopes", "allowedTools", "allowedResourceIds", "capability", "sessionLimits", "rateLimits"], "Remote profile");
  if (typeof value.id !== "string" || !ID.test(value.id) || value.capability !== "read-only") throw new OpsHavenError("CONFIG_INVALID", "Remote profile identity or capability is invalid.");
  const subjects = strings(value.subjects, 128, SUBJECT, `Remote profile ${value.id} subjects`);
  const requiredScopes = strings(value.requiredScopes, 32, SCOPE, `Remote profile ${value.id} scopes`, true);
  const allowedTools = strings(value.allowedTools, 32, ID, `Remote profile ${value.id} tools`);
  if (allowedTools.some((tool) => !REMOTE_READ_ONLY_TOOLS.has(tool))) throw new OpsHavenError("CONFIG_INVALID", `Remote profile ${value.id} exposes a non-read-only tool.`);
  const allowedResourceIds = strings(value.allowedResourceIds, 512, ID, `Remote profile ${value.id} resources`);
  if (allowedResourceIds.some((id) => !config.resources.has(id))) throw new OpsHavenError("CONFIG_INVALID", `Remote profile ${value.id} references an unknown resource.`);
  const session = limits(value.sessionLimits, `Remote profile ${value.id} session limits`);
  exact(session, ["maximumSessions", "lifetimeSeconds", "inactivitySeconds", "maximumPendingRequests"], `Remote profile ${value.id} session limits`);
  const rate = limits(value.rateLimits, `Remote profile ${value.id} rate limits`);
  exact(rate, ["windowSeconds", "maximumRequests", "concurrency"], `Remote profile ${value.id} rate limits`);
  return Object.freeze({
    id: value.id,
    subjects: Object.freeze(subjects),
    requiredScopes: Object.freeze(requiredScopes),
    allowedTools: Object.freeze(allowedTools),
    allowedResourceIds: Object.freeze(allowedResourceIds),
    capability: "read-only",
    sessionLimits: Object.freeze({
      maximumSessions: integer(session.maximumSessions, 1, 32, `Remote profile ${value.id} maximum sessions`),
      lifetimeSeconds: integer(session.lifetimeSeconds, 60, 86400, `Remote profile ${value.id} session lifetime`),
      inactivitySeconds: integer(session.inactivitySeconds, 30, 3600, `Remote profile ${value.id} inactivity timeout`),
      maximumPendingRequests: integer(session.maximumPendingRequests, 1, 32, `Remote profile ${value.id} pending requests`),
    }),
    rateLimits: Object.freeze({
      windowSeconds: integer(rate.windowSeconds, 1, 3600, `Remote profile ${value.id} rate window`),
      maximumRequests: integer(rate.maximumRequests, 1, 10000, `Remote profile ${value.id} request rate`),
      concurrency: integer(rate.concurrency, 1, 32, `Remote profile ${value.id} concurrency`),
    }),
  });
}

export function remoteConfigPath(configPath: string): string { return `${configPath}.remote.json`; }

export function parseRemoteMcpConfig(value: unknown, config: OpsHavenConfig): RemoteMcpConfig {
  if (!plain(value)) throw new OpsHavenError("CONFIG_INVALID", "Remote MCP configuration is malformed.");
  if (value.enabled === false) {
    exact(value, ["enabled"], "Disabled remote MCP configuration");
    return Object.freeze({ enabled: false });
  }
  exact(value, ["enabled", "bindHost", "port", "path", "allowedOrigins", "allowedHosts", "trustedProxies", "oauth", "profiles", "sessions", "requests", "rateLimits"], "Remote MCP configuration");
  if (value.enabled !== true || typeof value.bindHost !== "string" || !ADDRESS.test(value.bindHost) || typeof value.path !== "string" || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@\/-]{0,127}$/.test(value.path)) throw new OpsHavenError("CONFIG_INVALID", "Remote MCP listener configuration is invalid.");
  const port = integer(value.port, 1, 65535, "Remote MCP port");
  const allowedOrigins = strings(value.allowedOrigins, 64, /^https:\/\/[^\s/]+$/, "Remote MCP allowed origins").map((item) => origin(item, "Remote MCP origin"));
  const allowedHosts = strings(value.allowedHosts, 64, HOST, "Remote MCP allowed hosts");
  const trustedProxies = strings(value.trustedProxies, 64, ADDRESS, "Remote MCP trusted proxies", true);
  if (!plain(value.oauth)) throw new OpsHavenError("CONFIG_INVALID", "Remote MCP OAuth configuration is malformed.");
  exact(value.oauth, ["issuer", "audience", "requiredScopes", "allowedAlgorithms", "allowedJwksHosts", "metadataCacheSeconds", "keyCacheSeconds", "minimumRefreshSeconds", "fetchTimeoutMs", "clockSkewSeconds"], "Remote MCP OAuth configuration");
  const issuer = httpsUrl(value.oauth.issuer, "Remote MCP OAuth issuer").toString().replace(/\/$/, "");
  if (typeof value.oauth.audience !== "string" || !SUBJECT.test(value.oauth.audience)) throw new OpsHavenError("CONFIG_INVALID", "Remote MCP OAuth audience is invalid.");
  const requiredScopes = strings(value.oauth.requiredScopes, 32, SCOPE, "Remote MCP required scopes");
  const allowedAlgorithms = strings(value.oauth.allowedAlgorithms, 4, /^(?:RS256|PS256|ES256|EdDSA)$/, "Remote MCP allowed algorithms") as EnabledRemoteMcpConfig["oauth"]["allowedAlgorithms"];
  const allowedJwksHosts = strings(value.oauth.allowedJwksHosts, 16, /^[A-Za-z0-9.-]+$/, "Remote MCP allowed JWKS hosts");
  const profilesValue = value.profiles;
  if (!Array.isArray(profilesValue) || profilesValue.length === 0 || profilesValue.length > 64) throw new OpsHavenError("CONFIG_INVALID", "Remote MCP profiles must be a bounded non-empty array.");
  const profiles = profilesValue.map((item) => parseProfile(item, config));
  if (new Set(profiles.map((profile) => profile.id)).size !== profiles.length) throw new OpsHavenError("CONFIG_INVALID", "Remote MCP profile IDs must be unique.");
  const subjects = profiles.flatMap((profile) => profile.subjects);
  if (new Set(subjects).size !== subjects.length) throw new OpsHavenError("CONFIG_INVALID", "Each authenticated subject must map to exactly one remote profile.");
  const sessions = limits(value.sessions, "Remote MCP session limits");
  exact(sessions, ["maximumGlobal", "maximumPerPrincipal", "lifetimeSeconds", "inactivitySeconds", "maximumPendingPerSession"], "Remote MCP session limits");
  const requests = limits(value.requests, "Remote MCP request limits");
  exact(requests, ["maximumBodyBytes", "maximumHeaderBytes", "maximumHeaders", "maximumJsonDepth", "maximumJsonNodes", "timeoutMs", "maximumResponseBytes", "globalConcurrency", "perPrincipalConcurrency", "maximumQueue"], "Remote MCP request limits");
  const rateLimits = limits(value.rateLimits, "Remote MCP global rate limits");
  exact(rateLimits, ["windowSeconds", "maximumRequests"], "Remote MCP global rate limits");
  return Object.freeze({
    enabled: true,
    bindHost: value.bindHost,
    port,
    path: value.path,
    allowedOrigins: Object.freeze(allowedOrigins),
    allowedHosts: Object.freeze(allowedHosts),
    trustedProxies: Object.freeze(trustedProxies),
    oauth: Object.freeze({
      issuer,
      audience: value.oauth.audience,
      requiredScopes: Object.freeze(requiredScopes),
      allowedAlgorithms: Object.freeze([...allowedAlgorithms]),
      allowedJwksHosts: Object.freeze(allowedJwksHosts),
      metadataCacheSeconds: integer(value.oauth.metadataCacheSeconds, 60, 86400, "Remote MCP metadata cache lifetime"),
      keyCacheSeconds: integer(value.oauth.keyCacheSeconds, 60, 86400, "Remote MCP JWKS cache lifetime"),
      minimumRefreshSeconds: integer(value.oauth.minimumRefreshSeconds, 5, 3600, "Remote MCP minimum key refresh interval"),
      fetchTimeoutMs: integer(value.oauth.fetchTimeoutMs, 500, 15000, "Remote MCP provider fetch timeout"),
      clockSkewSeconds: integer(value.oauth.clockSkewSeconds, 0, 300, "Remote MCP token clock skew"),
    }),
    profiles: Object.freeze(profiles),
    sessions: Object.freeze({
      maximumGlobal: integer(sessions.maximumGlobal, 1, 1024, "Remote MCP maximum global sessions"),
      maximumPerPrincipal: integer(sessions.maximumPerPrincipal, 1, 64, "Remote MCP maximum principal sessions"),
      lifetimeSeconds: integer(sessions.lifetimeSeconds, 60, 86400, "Remote MCP session lifetime"),
      inactivitySeconds: integer(sessions.inactivitySeconds, 30, 3600, "Remote MCP session inactivity"),
      maximumPendingPerSession: integer(sessions.maximumPendingPerSession, 1, 64, "Remote MCP pending session requests"),
    }),
    requests: Object.freeze({
      maximumBodyBytes: integer(requests.maximumBodyBytes, 1024, 4194304, "Remote MCP body limit"),
      maximumHeaderBytes: integer(requests.maximumHeaderBytes, 1024, 65536, "Remote MCP header bytes"),
      maximumHeaders: integer(requests.maximumHeaders, 8, 128, "Remote MCP header count"),
      maximumJsonDepth: integer(requests.maximumJsonDepth, 4, 64, "Remote MCP JSON depth"),
      maximumJsonNodes: integer(requests.maximumJsonNodes, 32, 100000, "Remote MCP JSON nodes"),
      timeoutMs: integer(requests.timeoutMs, 500, 120000, "Remote MCP request timeout"),
      maximumResponseBytes: integer(requests.maximumResponseBytes, 1024, 4194304, "Remote MCP response limit"),
      globalConcurrency: integer(requests.globalConcurrency, 1, 128, "Remote MCP global concurrency"),
      perPrincipalConcurrency: integer(requests.perPrincipalConcurrency, 1, 32, "Remote MCP principal concurrency"),
      maximumQueue: integer(requests.maximumQueue, 0, 512, "Remote MCP queue limit"),
    }),
    rateLimits: Object.freeze({
      windowSeconds: integer(rateLimits.windowSeconds, 1, 3600, "Remote MCP global rate window"),
      maximumRequests: integer(rateLimits.maximumRequests, 1, 100000, "Remote MCP global rate"),
    }),
  });
}

export async function loadRemoteMcpConfig(configPath: string, config: OpsHavenConfig): Promise<RemoteMcpConfig> {
  const text = await readOptionalRegularTextFile(remoteConfigPath(configPath), "Remote MCP configuration", { maxBytes: 1048576, code: "CONFIG_INVALID" });
  if (text === "") return Object.freeze({ enabled: false });
  let parsed: unknown;
  try { parsed = JSON.parse(text) as unknown; }
  catch { throw new OpsHavenError("CONFIG_INVALID", "Remote MCP configuration is invalid JSON."); }
  return parseRemoteMcpConfig(parsed, config);
}
