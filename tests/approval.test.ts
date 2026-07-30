import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import type { ResolvedOperation } from "../src/policy/operations.js";
import {
  ApprovalVerifier,
  createApprovalRequest,
  signApprovalRequest
} from "../src/security/approval.js";
import { OpsHavenError } from "../src/core/errors.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map(async (directory) => await rm(directory, { recursive: true, force: true })));
});

const operation: ResolvedOperation = {
  requestId: "00000000-0000-4000-8000-000000000000",
  operation: "restart_service",
  kind: "mutation",
  target: "demo-service",
  hostId: "demo-host",
  args: { serviceId: "demo-service" },
  expectedState: { activeState: "active" },
  policyVersion: "v1",
  timeoutMs: 10_000,
  output: { maxBytes: 4096, maxLines: 50 },
  dryRun: false,
  requiresApproval: true
};

async function verifier(now = new Date("2026-01-01T00:00:01.000Z")): Promise<ApprovalVerifier> {
  const directory = await mkdtemp(join(tmpdir(), "opshaven-approval-"));
  directories.push(directory);
  return new ApprovalVerifier(directory, Buffer.from("k".repeat(64)), () => now);
}

describe("exact single-use human approval", () => {
  it("accepts one valid approval bound to exact arguments and expected state", async () => {
    const request = createApprovalRequest(
      operation,
      300,
      () => new Date("2026-01-01T00:00:00.000Z"),
      "nonce-abcdefghijklmnop"
    );
    const token = signApprovalRequest(request, Buffer.from("k".repeat(64)));
    const service = await verifier();
    await service.verifyAndConsume(operation, token);
    await assert.rejects(() => service.verifyAndConsume(operation, token), (error: unknown) => {
      assert.ok(error instanceof OpsHavenError);
      assert.equal(error.code, "APPROVAL_REPLAYED");
      return true;
    });
  });

  it("rejects argument, target, expected-state, and policy mutation", async () => {
    const request = createApprovalRequest(
      operation,
      300,
      () => new Date("2026-01-01T00:00:00.000Z"),
      "nonce-abcdefghijklmnop"
    );
    const token = signApprovalRequest(request, Buffer.from("k".repeat(64)));
    for (const changed of [
      { ...operation, args: { serviceId: "other-service" } },
      { ...operation, target: "other-service" },
      { ...operation, expectedState: { activeState: "failed" } },
      { ...operation, policyVersion: "v2" }
    ]) {
      const service = await verifier();
      await assert.rejects(() => service.verifyAndConsume(changed, token), OpsHavenError);
    }
  });

  it("rejects expired and forged tokens", async () => {
    const request = createApprovalRequest(
      operation,
      30,
      () => new Date("2026-01-01T00:00:00.000Z"),
      "nonce-abcdefghijklmnop"
    );
    const token = signApprovalRequest(request, Buffer.from("k".repeat(64)));
    const expired = await verifier(new Date("2026-01-01T00:01:00.000Z"));
    await assert.rejects(() => expired.verifyAndConsume(operation, token), OpsHavenError);
    const forged = await verifier();
    await assert.rejects(() => forged.verifyAndConsume(operation, { ...token, mac: "A".repeat(43) }), OpsHavenError);
  });
});
