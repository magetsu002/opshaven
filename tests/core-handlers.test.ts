import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, describe, it } from "node:test";
import type { OpsHavenConfig } from "../src/config/schema.js";
import { parseConfig } from "../src/config/schema.js";
import { createCoreHandlers } from "../src/dispatcher/core-handlers.js";
import { Dispatcher } from "../src/dispatcher/dispatcher.js";
import type { ProcessRequest, ProcessResult } from "../src/transport/process.js";

let config: OpsHavenConfig;
const base = {
  version: 1 as const,
  requestId: "00000000-0000-4000-8000-000000000000",
  target: "demo-service",
  expectedState: {},
  dryRun: false,
  limits: { timeoutMs: 1000, maxBytes: 4096, maxLines: 50 }
};

before(async () => {
  config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
});

function output(stdout: string, exitCode = 0): ProcessResult {
  return { exitCode, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) };
}

describe("core inspection handlers", () => {
  it("resolves configured service units without accepting agent commands", async () => {
    const calls: ProcessRequest[] = [];
    const handlers = createCoreHandlers({
      runner: async (request) => {
        calls.push(request);
        return output("Id=demo.service\nActiveState=active\nSubState=running\nMainPID=123\n");
      }
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({
      ...base,
      operation: "get_service_status",
      args: { serviceId: "demo-service" }
    });
    assert.equal(response.ok, true);
    assert.deepEqual(calls[0]?.args.slice(0, 2), ["show", "demo.service"]);
    assert.equal(calls[0]?.executable, "/usr/bin/systemctl");
  });

  it("reports environment key presence without returning values", async () => {
    const handlers = createCoreHandlers({ runner: async () => output("NODE_ENV=\nSECRET_TOKEN=\n") });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({
      ...base,
      operation: "get_runtime_config_status",
      args: { serviceId: "demo-service" }
    });
    assert.equal(response.ok, true);
    const serialized = JSON.stringify(response);
    assert.ok(serialized.includes("NODE_ENV"));
    assert.ok(!serialized.includes("SECRET_TOKEN="));
    assert.ok(serialized.includes("\"valuesExposed\":false"));
  });

  it("rejects resources assigned to another host", async () => {
    const foreign = {
      ...config,
      hosts: [...config.hosts, { ...config.hosts[0]!, id: "other-host" }],
      services: [...config.services, { ...config.services[0]!, id: "other-service", hostId: "other-host" }]
    };
    const handlers = createCoreHandlers({ runner: async () => output("") });
    const response = await new Dispatcher(foreign, handlers, "demo-host").handle({
      ...base,
      target: "other-service",
      operation: "get_service_status",
      args: { serviceId: "other-service" }
    });
    assert.equal(response.ok, false);
  });
});
