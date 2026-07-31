import type { BoundaryAssertion } from "../boundary.js";
import type { OpsHavenConfig } from "../config.js";
import { MUTATION_TOOL_NAMES } from "../mcp.js";
import { loadRemoteMcpConfig, type RemoteMcpConfig } from "./config.js";

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);
export interface RemoteTrustSummary {
  readonly enabled: boolean;
  readonly bindAddress?: string;
  readonly path?: string;
  readonly authentication: "disabled" | "oidc-bearer";
  readonly allowedOrigins: readonly string[];
  readonly allowedHosts: readonly string[];
  readonly trustedProxies: readonly string[];
  readonly effectiveTools: Readonly<Record<string, readonly string[]>>;
  readonly readOnly: boolean;
}

function assertion(name: string, passed: boolean, detail: string): BoundaryAssertion { return { name, passed, detail }; }
function tools(config: RemoteMcpConfig): Readonly<Record<string, readonly string[]>> {
  if (!config.enabled) return Object.freeze({});
  return Object.freeze(Object.fromEntries(config.profiles.map((profile) => [profile.id, Object.freeze([...profile.allowedTools])])));
}

export function summarizeRemoteTrust(config: RemoteMcpConfig): RemoteTrustSummary {
  if (!config.enabled) return Object.freeze({ enabled: false, authentication: "disabled", allowedOrigins: [], allowedHosts: [], trustedProxies: [], effectiveTools: Object.freeze({}), readOnly: true });
  const mutationExposed = config.profiles.some((profile) => profile.allowedTools.some((tool) => MUTATION_TOOL_NAMES.has(tool)));
  return Object.freeze({
    enabled: true,
    bindAddress: `${config.bindHost}:${config.port}`,
    path: config.path,
    authentication: "oidc-bearer",
    allowedOrigins: Object.freeze([...config.allowedOrigins]),
    allowedHosts: Object.freeze([...config.allowedHosts]),
    trustedProxies: Object.freeze([...config.trustedProxies]),
    effectiveTools: tools(config),
    readOnly: !mutationExposed && config.profiles.every((profile) => profile.capability === "read-only"),
  });
}

export function remoteBoundaryAssertions(config: RemoteMcpConfig): BoundaryAssertion[] {
  if (!config.enabled) return [assertion("remote MCP disabled by default", true, "no network listener is configured")];
  const loopback = LOOPBACK.has(config.bindHost);
  const origins = config.allowedOrigins.length > 0 && config.allowedOrigins.every((origin) => origin.startsWith("https://") && !origin.includes("*"));
  const hosts = config.allowedHosts.length > 0 && config.allowedHosts.every((host) => !host.includes("*") && host !== "0.0.0.0" && host !== "::");
  const authentication = config.oauth.issuer.startsWith("https://") && config.oauth.audience.length > 0 && config.oauth.requiredScopes.length > 0 && config.oauth.allowedAlgorithms.length > 0;
  const readOnly = config.profiles.every((profile) => profile.capability === "read-only" && profile.allowedTools.every((tool) => !MUTATION_TOOL_NAMES.has(tool)));
  return [
    assertion("remote listener is loopback-only", loopback, loopback ? `${config.bindHost}:${config.port}` : "public listeners are outside the certified boundary"),
    assertion("remote authentication is mandatory", authentication, "OIDC bearer signature, issuer, audience, time, and scope verification"),
    assertion("remote origins are exact HTTPS values", origins, `${config.allowedOrigins.length} reviewed origin(s)`),
    assertion("remote hosts are exact trusted values", hosts, `${config.allowedHosts.length} reviewed host value(s)`),
    assertion("remote tools are read-only", readOnly, "mutation operations absent from every remote profile"),
    assertion("forwarded headers have explicit proxy trust", true, config.trustedProxies.length ? `${config.trustedProxies.length} reviewed proxy address(es)` : "forwarded headers rejected"),
  ];
}

export async function loadRemoteTrust(configPath: string, config: OpsHavenConfig): Promise<{ config: RemoteMcpConfig; summary: RemoteTrustSummary; assertions: BoundaryAssertion[] }> {
  const remote = await loadRemoteMcpConfig(configPath, config);
  return { config: remote, summary: summarizeRemoteTrust(remote), assertions: remoteBoundaryAssertions(remote) };
}

export function remoteMcpUrl(config: RemoteMcpConfig): string {
  if (!config.enabled) throw new Error("Remote MCP is disabled.");
  const host = config.bindHost.includes(":") ? `[${config.bindHost}]` : config.bindHost;
  return `http://${host}:${config.port}${config.path}`;
}
