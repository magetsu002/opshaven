import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, describe, it } from "node:test";
import type { OpsHavenConfig } from "../src/config/schema.js";
import { parseConfig } from "../src/config/schema.js";
import { OpsHavenError } from "../src/core/errors.js";
import { resolveOperation } from "../src/policy/operations.js";

let config: OpsHavenConfig;

before(async () => {
  config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
});

describe("fail-closed policy engine", () => {
  it("resolves only configured logical IDs", () => {
    const operation = resolveOperation(config, "get_service_status", { serviceId: "demo-service" });
    assert.equal(operation.hostId, "demo-host");
    assert.deepEqual(operation.args, { serviceId: "demo-service" });
    assert.equal(operation.requiresApproval, false);
  });

  it("rejects unknown operations, fields, and resources", () => {
    assert.throws(() => resolveOperation(config, "run_shell", {}), OpsHavenError);
    assert.throws(
      () => resolveOperation(config, "get_service_status", { serviceId: "demo-service", command: "id" }),
      OpsHavenError
    );
    assert.throws(() => resolveOperation(config, "get_service_status", { serviceId: "missing" }), OpsHavenError);
  });

  it("binds mutation expected state and dry-run behavior", () => {
    const restart = resolveOperation(config, "restart_service", {
      serviceId: "demo-service",
      expectedActiveState: "active"
    });
    assert.equal(restart.requiresApproval, true);
    assert.deepEqual(restart.expectedState, { activeState: "active" });

    const dryRun = resolveOperation(config, "restart_service", {
      serviceId: "demo-service",
      expectedActiveState: "active",
      dryRun: true
    });
    assert.equal(dryRun.requiresApproval, false);
    assert.equal(dryRun.dryRun, true);
  });

  it("rejects malformed commits and unacknowledged migration risk", () => {
    assert.throws(
      () =>
        resolveOperation(config, "deploy_commit", {
          deploymentId: "demo-deployment",
          commit: "main",
          expectedCurrentCommit: "a".repeat(40)
        }),
      OpsHavenError
    );
    assert.throws(
      () =>
        resolveOperation(config, "deploy_commit", {
          deploymentId: "demo-deployment",
          commit: "b".repeat(40),
          expectedCurrentCommit: "a".repeat(40)
        }),
      OpsHavenError
    );
  });
});
