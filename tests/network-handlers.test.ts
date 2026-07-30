import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, describe, it } from "node:test";
import type { OpsHavenConfig } from "../src/config/schema.js";
import { parseConfig } from "../src/config/schema.js";
import { Dispatcher } from "../src/dispatcher/dispatcher.js";
import { createNetworkHandlers } from "../src/dispatcher/network-handlers.js";
import type { ProcessRequest, ProcessResult } from "../src/transport/process.js";

let config: OpsHavenConfig;
const base = {
  version: 1 as const,
  requestId: "00000000-0000-4000-8000-000000000000",
  expectedState: {},
  dryRun: false,
  limits: { timeoutMs: 1000, maxBytes: 4096, maxLines: 50 }
};

before(async () => {
  const raw = JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as Record<string, unknown>;
  raw["proxies"] = [
    {
      id: "demo-proxy",
      hostId: "demo-host",
      provider: "nginx",
      serviceId: "demo-service",
      routes: [{ hostname: "demo.invalid", pathPrefix: "/", upstreamId: "demo-service" }]
    }
  ];
  config = parseConfig(raw);
});

function output(stdout: string): ProcessResult {
  return { exitCode: 0, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) };
}

describe("network inspection handlers", () => {
  it("summarizes firewall state without exposing raw rules", async () => {
    const calls: ProcessRequest[] = [];
    const handlers = createNetworkHandlers({
      runner: async (request) => {
        calls.push(request);
        return output("Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo Action From\n-- ------ ----\n22 ALLOW 192.0.2.1\n");
      },
      fetcher: async () => new Response(null, { status: 200 }),
      clock: () => 0
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({
      ...base,
      target: "demo-host",
      operation: "get_firewall_summary",
      args: { hostId: "demo-host" }
    });
    assert.equal(response.ok, true);
    assert.ok(!JSON.stringify(response).includes("192.0.2.1"));
    assert.deepEqual(calls[0]?.args, ["status", "verbose"]);
  });

  it("runs only the configured health URL and discards the body", async () => {
    let requested = "";
    const handlers = createNetworkHandlers({
      runner: async () => output(""),
      fetcher: async (url) => {
        requested = url;
        return new Response("secret body", { status: 200 });
      },
      clock: (() => {
        let value = 10;
        return () => (value += 5);
      })()
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({
      ...base,
      target: "demo-health",
      operation: "run_health_probe",
      args: { probeId: "demo-health" }
    });
    assert.equal(requested, "http://127.0.0.1:8080/health");
    assert.ok(!JSON.stringify(response).includes("secret body"));
  });
});
