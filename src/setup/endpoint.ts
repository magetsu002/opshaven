import { promises as fs } from "node:fs";
import path from "node:path";
import { loadConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { parseRemoteMcpConfig, remoteConfigPath, type EnabledRemoteMcpConfig } from "../remote-mcp/config.js";
import { readRegularTextFile } from "../safe-fs.js";
import { readRemoteCertification } from "./certify.js";
import type { RemoteSetupConfig } from "./remote.js";

export interface EndpointHandoffReceipt {
  readonly ok: true;
  readonly status: "prepared" | "verified";
  readonly localUrl: string;
  readonly externalUrl: string;
  readonly authentication: "oidc-bearer";
  readonly boundarySha256: string;
  readonly instructions: readonly string[];
  readonly externalStatus: number | null;
}

export interface EndpointHandoffRuntime {
  certification(setup: RemoteSetupConfig): Promise<{ certified: boolean; boundarySha256: string | null; sourceSha: string | null }>;
  verify(url: string): Promise<{ status: number; body: string; headers: Record<string, string> }>;
}

function loopback(value: string): boolean {
  return value === "127.0.0.1" || value === "::1" || value === "localhost";
}

function externalUrl(value: string, expectedPath: string): URL {
  let parsed: URL;
  try { parsed = new URL(value); }
  catch { throw new OpsHavenError("CONFIG_INVALID", "External endpoint must be a valid HTTPS URL."); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== expectedPath) throw new OpsHavenError("CONFIG_INVALID", `External endpoint must be credential-free HTTPS with exact path ${expectedPath}.`);
  return parsed;
}

async function atomicWrite(filePath: string, text: string): Promise<void> {
  const temporary = `${filePath}.opshaven-${process.pid}`;
  try {
    await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
    await fs.writeFile(temporary, text, { mode: 0o600 });
    await fs.chmod(temporary, 0o600);
    await fs.rename(temporary, filePath);
  } finally { await fs.rm(temporary, { force: true }); }
}

function validateEndpointConfig(config: EnabledRemoteMcpConfig, external: URL): void {
  if (!loopback(config.bindHost)) throw new OpsHavenError("POLICY_DENIED", "Endpoint handoff refuses a public or non-loopback OpsHaven bind address.");
  if (config.path !== external.pathname) throw new OpsHavenError("CONFIG_INVALID", "External HTTPS path does not match the MCP path.");
  if (!config.allowedHosts.includes(external.host)) throw new OpsHavenError("CONFIG_INVALID", "External host is absent from allowedHosts.");
  if (!config.allowedOrigins.includes(external.origin)) throw new OpsHavenError("CONFIG_INVALID", "External origin is absent from allowedOrigins.");
  if (config.trustedProxies.length === 0 || config.trustedProxies.some((item) => !loopback(item))) throw new OpsHavenError("CONFIG_INVALID", "Endpoint handoff requires an explicit loopback-only trusted proxy set.");
  if (config.oauth.requiredScopes.length === 0 || config.oauth.allowedJwksHosts.length === 0 || config.profiles.length === 0) throw new OpsHavenError("CONFIG_INVALID", "OIDC issuer, JWKS, scopes, and profiles must remain explicit.");
  if (config.sessions.maximumGlobal < config.sessions.maximumPerPrincipal || config.requests.globalConcurrency < config.requests.perPrincipalConcurrency) throw new OpsHavenError("CONFIG_INVALID", "Global endpoint limits cannot be narrower than per-principal limits.");
  if (config.requests.maximumBodyBytes > config.requests.maximumResponseBytes * 4) throw new OpsHavenError("CONFIG_INVALID", "Request and response bounds are disproportionate.");
}

function defaultRuntime(): EndpointHandoffRuntime {
  return {
    certification: async (setup) => await readRemoteCertification(setup),
    verify: async (url) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      try {
        const response = await fetch(url, {
          method: "POST",
          headers: {
            accept: "application/json, text/event-stream",
            "content-type": "application/json",
            "mcp-protocol-version": "2026-07-28",
            "mcp-method": "tools/list",
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: "endpoint-verification", method: "tools/list", params: {} }),
          redirect: "error",
          signal: controller.signal,
        });
        const body = (await response.text()).slice(0, 4096);
        return { status: response.status, body, headers: { "www-authenticate": response.headers.get("www-authenticate") ?? "", "access-control-allow-origin": response.headers.get("access-control-allow-origin") ?? "" } };
      } finally { clearTimeout(timer as any); }
    },
  };
}

function instructions(config: EnabledRemoteMcpConfig, external: URL): readonly string[] {
  const localHost = config.bindHost === "::1" ? "[::1]" : config.bindHost;
  return Object.freeze([
    `Start OpsHaven locally: opshaven serve --transport streamable-http --config <policy-config> --bind ${config.bindHost} --port ${config.port} --path ${config.path}`,
    `Configure an HTTPS reverse proxy or authenticated tunnel from ${external.origin}${config.path} to http://${localHost}:${config.port}${config.path}.`,
    "Preserve the exact Host header and send one unambiguous X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto=https set from the configured loopback proxy.",
    "Do not terminate or bypass bearer-token verification in the proxy; OpsHaven must validate issuer, audience, signature, scopes, subject mapping, session, replay, rate, and request limits.",
  ]);
}

export async function exposeEndpoint(
  setup: RemoteSetupConfig,
  endpointConfigPath: string,
  externalValue: string,
  verifyExternal: boolean,
  injected?: EndpointHandoffRuntime,
): Promise<EndpointHandoffReceipt> {
  const runtime = injected ?? defaultRuntime();
  const certification = await runtime.certification(setup);
  if (!certification.certified || !certification.boundarySha256) throw new OpsHavenError("POLICY_DENIED", "Endpoint setup is blocked until exact remote boundary certification passes.");
  let raw: unknown;
  try { raw = JSON.parse(await readRegularTextFile(endpointConfigPath, "Endpoint companion configuration", { ownerOnly: true, maxBytes: 262144, code: "CONFIG_INVALID" })) as unknown; }
  catch (error) {
    if (error instanceof OpsHavenError) throw error;
    throw new OpsHavenError("CONFIG_INVALID", "Endpoint companion configuration is invalid JSON.");
  }
  const policy = await loadConfig(setup.policyConfigPath);
  const parsed = parseRemoteMcpConfig(raw, policy);
  if (!parsed.enabled) throw new OpsHavenError("CONFIG_INVALID", "Endpoint companion configuration must explicitly enable remote MCP.");
  const external = externalUrl(externalValue, parsed.path);
  validateEndpointConfig(parsed, external);
  await atomicWrite(remoteConfigPath(setup.policyConfigPath), `${JSON.stringify(raw, null, 2)}\n`);
  let externalStatus: number | null = null;
  let status: "prepared" | "verified" = "prepared";
  if (verifyExternal) {
    const result = await runtime.verify(external.toString());
    externalStatus = result.status;
    const anonymousDenied = result.status === 401 || result.status === 403;
    const challengePresent = /Bearer/i.test(result.headers["www-authenticate"] ?? "") || /AUTH|TOKEN|UNAUTHORIZED/i.test(result.body);
    const corsNotReflected = result.headers["access-control-allow-origin"] !== "*";
    if (!anonymousDenied || !challengePresent || !corsNotReflected) throw new OpsHavenError("POLICY_DENIED", "External HTTPS path did not prove that anonymous MCP access remains denied by OIDC.");
    status = "verified";
  }
  return Object.freeze({ ok: true, status, localUrl: `http://${parsed.bindHost === "::1" ? "[::1]" : parsed.bindHost}:${parsed.port}${parsed.path}`, externalUrl: external.toString(), authentication: "oidc-bearer", boundarySha256: certification.boundarySha256, instructions: instructions(parsed, external), externalStatus });
}

export async function endpointStatus(setup: RemoteSetupConfig, injected?: EndpointHandoffRuntime): Promise<Record<string, unknown>> {
  const certification = await (injected ?? defaultRuntime()).certification(setup);
  const policy = await loadConfig(setup.policyConfigPath);
  let remote;
  try {
    const text = await readRegularTextFile(remoteConfigPath(setup.policyConfigPath), "Installed endpoint companion configuration", { ownerOnly: true, maxBytes: 262144, code: "CONFIG_INVALID" });
    remote = parseRemoteMcpConfig(JSON.parse(text) as unknown, policy);
  } catch { remote = { enabled: false } as const; }
  return Object.freeze({ ok: certification.certified && remote.enabled, certified: certification.certified, boundarySha256: certification.boundarySha256, sourceSha: certification.sourceSha, remoteMcp: remote.enabled ? { enabled: true, bindHost: remote.bindHost, port: remote.port, path: remote.path, oauthIssuer: remote.oauth.issuer, profiles: remote.profiles.map((item) => item.id) } : { enabled: false } });
}
