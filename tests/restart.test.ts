import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, describe, it } from "node:test";
import type { OpsHavenConfig } from "../src/config/schema.js";
import { parseConfig } from "../src/config/schema.js";
import { Dispatcher } from "../src/dispatcher/dispatcher.js";
import { createMutationHandlers } from "../src/dispatcher/mutation-handlers.js";
import type { ProcessRequest, ProcessResult } from "../src/transport/process.js";

let config: OpsHavenConfig;
const request = {
  version: 1 as const,
  requestId: "00000000-0000-4000-8000-000000000000",
  operation: "restart_service" as const,
  target: "demo-service",
  args: { serviceId: "demo-service" },
  expectedState: { activeState: "active" },
  dryRun: false,
  limits: { timeoutMs: 1000, maxBytes: 4096, maxLines: 50 }
};

before(async () => {
  config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
});

function output(stdout: string, exitCode = 0): ProcessResult {
  return { exitCode, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) };
}

describe("controlled service restart", () => {
  it("dry-run verifies state but makes no change", async () => {
    const calls: ProcessRequest[] = [];
    const handlers = createMutationHandlers({
      runner: async (call) => {
        calls.push(call);
        return output("active");
      }
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({ ...request, dryRun: true });
    assert.equal(response.ok, true);
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.executable, "/usr/bin/systemctl");
  });

  it("refuses restart when current state differs from approved state", async () => {
    const handlers = createMutationHandlers({ runner: async () => output("failed", 3) });
    const response = await new Dispatcher(config, handlers, "demo-host").handle(request);
    assert.equal(response.ok, false);
  });

  it("uses exact configured sudo restart and verifies active state", async () => {
    const calls: ProcessRequest[] = [];
    const handlers = createMutationHandlers({
      runner: async (call) => {
        calls.push(call);
        return output(calls.length === 2 ? "" : "active");
      }
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle(request);
    assert.equal(response.ok, true);
    assert.deepEqual(calls[1]?.args, ["-n", "/usr/bin/systemctl", "restart", "demo.service"]);
    assert.equal(calls[1]?.executable, "/usr/bin/sudo");
  });
});
