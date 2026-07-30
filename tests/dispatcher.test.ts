import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, describe, it } from "node:test";
import type { OpsHavenConfig } from "../src/config/schema.js";
import { parseConfig } from "../src/config/schema.js";
import { Dispatcher } from "../src/dispatcher/dispatcher.js";
import { parseDispatcherRequest } from "../src/dispatcher/protocol.js";

let config: OpsHavenConfig;
const request = {
  version: 1,
  requestId: "00000000-0000-4000-8000-000000000000",
  operation: "get_host_summary",
  target: "demo-host",
  args: { hostId: "demo-host" },
  expectedState: {},
  dryRun: false,
  limits: { timeoutMs: 1000, maxBytes: 4096, maxLines: 20 }
};

before(async () => {
  config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
});

describe("forced-command dispatcher", () => {
  it("independently validates the strict remote protocol", () => {
    assert.equal(parseDispatcherRequest(request).operation, "get_host_summary");
    assert.throws(() => parseDispatcherRequest({ ...request, command: "id" }));
    assert.throws(() => parseDispatcherRequest({ ...request, limits: { ...request.limits, maxBytes: 9_999_999 } }));
  });

  it("fails closed when a fixed handler is absent", async () => {
    const response = await new Dispatcher(config, {}, "demo-host").handle(request);
    assert.equal(response.ok, false);
    if (!response.ok) assert.equal(response.error.code, "POLICY_DENIED");
  });

  it("uses only an immutable handler registry", async () => {
    const handlers = {
      get_host_summary: async () => ({ kernel: "generic" })
    } as const;
    const dispatcher = new Dispatcher(config, handlers, "demo-host");
    const response = await dispatcher.handle(request);
    assert.equal(response.ok, true);
  });
});
