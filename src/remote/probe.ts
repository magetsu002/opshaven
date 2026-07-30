import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { ProbeResource } from "../config.js";
import { OpsHavenError } from "../errors.js";

export interface ProbeResult { reachable: boolean; statusCode?: number; latencyMs: number; expected: boolean }

export async function runProbe(probe: ProbeResource): Promise<ProbeResult> {
  const url = new URL(probe.url);
  const request = url.protocol === "https:" ? httpsRequest : httpRequest;
  const started = Date.now();
  return await new Promise<ProbeResult>((resolve, reject) => {
    const req = request({ protocol: url.protocol, hostname: url.hostname, port: url.port || undefined, path: url.pathname, method: probe.method, timeout: probe.timeoutMs, headers: { "user-agent": "opshaven-probe/1" } }, (response: any) => {
      const statusCode = Number(response.statusCode ?? 0);
      response.resume();
      resolve({ reachable: true, statusCode, latencyMs: Date.now() - started, expected: probe.expectedStatus.includes(statusCode) });
    });
    req.on("timeout", () => { req.destroy(); reject(new OpsHavenError("TIMEOUT", "Health probe timed out.", true)); });
    req.on("error", () => reject(new OpsHavenError("REMOTE_OPERATION_FAILED", "Health probe failed.", true)));
    req.end();
  });
}
