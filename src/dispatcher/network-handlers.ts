import { performance } from "node:perf_hooks";
import type { JsonValue } from "../security/canonical.js";
import type { DispatcherHandlers } from "./dispatcher.js";
import {
  assertArgs,
  assertTarget,
  DEFAULT_RUNTIME,
  findResource,
  fixedCommand,
  type HandlerRuntime
} from "./runtime.js";

export type SafeFetch = (
  input: string,
  init: Readonly<{ method: "GET"; redirect: "manual"; signal: AbortSignal; headers: Readonly<Record<string, string>> }>
) => Promise<Response>;

export type NetworkRuntime = HandlerRuntime & Readonly<{ fetcher: SafeFetch; clock: () => number }>;

const DEFAULT_NETWORK_RUNTIME: NetworkRuntime = Object.freeze({
  ...DEFAULT_RUNTIME,
  fetcher: async (input, init) => await fetch(input, init),
  clock: () => performance.now()
});

function parseSystemdActive(text: string): { activeState: string; subState: string } {
  const entries = Object.fromEntries(
    text
      .split("\n")
      .map((line) => line.split("=", 2))
      .filter((parts): parts is [string, string] => parts.length === 2)
  );
  return { activeState: entries["ActiveState"] ?? "unknown", subState: entries["SubState"] ?? "unknown" };
}

function summarizeUfw(text: string): JsonValue {
  const lines = text.split("\n").map((line) => line.trim()).filter(Boolean);
  const status = lines.find((line) => line.startsWith("Status:"))?.split(":", 2)[1]?.trim() ?? "unknown";
  const defaults = lines.find((line) => line.startsWith("Default:"))?.slice("Default:".length).trim() ?? "unknown";
  const separatorIndex = lines.findIndex((line) => /^-+$/.test(line.replace(/\s/g, "")));
  const ruleCount = separatorIndex < 0 ? 0 : lines.slice(separatorIndex + 1).filter((line) => !line.startsWith("(")) .length;
  return { provider: "ufw", status, defaults, ruleCount, rawRulesExposed: false };
}

function countNftables(value: unknown): { tables: number; chains: number; rules: number } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { tables: 0, chains: 0, rules: 0 };
  const nftables = (value as Record<string, unknown>)["nftables"];
  if (!Array.isArray(nftables)) return { tables: 0, chains: 0, rules: 0 };
  let tables = 0;
  let chains = 0;
  let rules = 0;
  for (const item of nftables) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) continue;
    const record = item as Record<string, unknown>;
    if ("table" in record) tables += 1;
    if ("chain" in record) chains += 1;
    if ("rule" in record) rules += 1;
  }
  return { tables, chains, rules };
}

export function createNetworkHandlers(runtime: NetworkRuntime = DEFAULT_NETWORK_RUNTIME): DispatcherHandlers {
  return {
    get_reverse_proxy_summary: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["proxyId"]);
      const proxy = findResource(config.proxies, request.args.proxyId, dispatcherHostId, "proxy");
      assertTarget(request, proxy.id);
      const service = findResource(config.services, proxy.serviceId, dispatcherHostId, "service");
      const status = await fixedCommand(runtime, request, "/usr/bin/systemctl", [
        "show",
        service.unit,
        "--no-page",
        "--property=ActiveState,SubState"
      ]);
      return {
        proxyId: proxy.id,
        provider: proxy.provider,
        service: parseSystemdActive(status.stdout),
        routes: proxy.routes.map((route) => ({
          hostname: route.hostname,
          pathPrefix: route.pathPrefix,
          upstreamId: route.upstreamId
        })),
        rawConfigurationExposed: false
      };
    },

    get_firewall_summary: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["hostId"]);
      if (request.args.hostId !== dispatcherHostId) throw new Error("Host is not served by this dispatcher");
      assertTarget(request, dispatcherHostId);
      const host = config.hosts.find((item) => item.id === dispatcherHostId)!;
      if (host.firewallProvider === "ufw") {
        const status = await fixedCommand(runtime, request, "/usr/sbin/ufw", ["status", "verbose"]);
        return summarizeUfw(status.stdout);
      }
      const status = await fixedCommand(runtime, request, "/usr/sbin/nft", ["--json", "list", "ruleset"]);
      const counts = countNftables(JSON.parse(status.stdout) as unknown);
      return { provider: "nftables", ...counts, rawRulesExposed: false };
    },

    run_health_probe: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["probeId"]);
      const probe = findResource(config.probes, request.args.probeId, dispatcherHostId, "probe");
      assertTarget(request, probe.id);
      const startedAt = runtime.clock();
      const response = await runtime.fetcher(probe.url, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(Math.min(probe.timeoutMs, request.limits.timeoutMs)),
        headers: { Accept: "application/json,text/plain;q=0.5" }
      });
      const durationMs = Math.max(0, Math.round(runtime.clock() - startedAt));
      await response.body?.cancel();
      return {
        probeId: probe.id,
        status: response.status,
        expected: probe.expectedStatus.includes(response.status),
        durationMs,
        bodyExposed: false,
        redirected: response.status >= 300 && response.status < 400
      };
    }
  };
}
