import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, describe, it } from "node:test";
import type { OpsHavenConfig } from "../src/config/schema.js";
import { parseConfig } from "../src/config/schema.js";
import { Dispatcher } from "../src/dispatcher/dispatcher.js";
import { createRecoveryHandlers } from "../src/dispatcher/recovery-handlers.js";
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
  config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
});

function output(stdout: string, exitCode = 0): ProcessResult {
  return { exitCode, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) };
}

describe("monitoring and recovery evidence", () => {
  it("checks only configured monitoring services", async () => {
    const calls: ProcessRequest[] = [];
    const handlers = createRecoveryHandlers({
      runner: async (request) => {
        calls.push(request);
        return output("active");
      },
      now: () => 1_000_000
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({
      ...base,
      target: "demo-monitoring",
      operation: "get_monitoring_status",
      args: { monitoringId: "demo-monitoring" }
    });
    assert.equal(response.ok, true);
    assert.deepEqual(calls[0]?.args, ["is-active", "demo.service"]);
  });

  it("reports backup freshness from metadata without reading evidence contents", async () => {
    const calls: ProcessRequest[] = [];
    const handlers = createRecoveryHandlers({
      runner: async (request) => {
        calls.push(request);
        return output("900|128");
      },
      now: () => 1_000_000
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({
      ...base,
      target: "demo-backup",
      operation: "get_backup_status",
      args: { backupId: "demo-backup" }
    });
    assert.equal(response.ok, true);
    assert.equal(calls[0]?.executable, "/usr/bin/stat");
    assert.ok(!calls[0]?.args.includes("cat"));
    assert.ok(JSON.stringify(response).includes("evidenceContentExposed"));
  });

  it("requires both backup evidence and a restore procedure", async () => {
    let calls = 0;
    const handlers = createRecoveryHandlers({
      runner: async () => {
        calls += 1;
        return calls === 1 ? output("999|128") : output("999|512");
      },
      now: () => 1_000_000
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({
      ...base,
      target: "demo-backup",
      operation: "get_restore_readiness",
      args: { backupId: "demo-backup" }
    });
    assert.equal(response.ok, true);
    assert.ok(JSON.stringify(response).includes("databaseMigrationsAutomaticallyReversed"));
  });
});
