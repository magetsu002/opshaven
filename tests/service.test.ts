import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { parseConfig, type OpsHavenConfig } from "../src/config/schema.js";
import { signApprovalRequest, type ApprovalRequest } from "../src/security/approval.js";
import { AuditLog, verifyAuditLog } from "../src/security/audit.js";
import type { JsonValue } from "../src/security/canonical.js";
import { OperationsService, type OperationTransport } from "../src/service/operations-service.js";

const roots: string[] = [];
const KEY = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");

async function fixture(): Promise<Readonly<{ config: OpsHavenConfig; root: string }>> {
  const root = await fs.mkdtemp("/tmp/opshaven-service-");
  roots.push(root);
  const raw = JSON.parse(await fs.readFile("examples/opshaven.config.json", "utf8")) as {
    audit: Record<string, unknown>;
    approvals: Record<string, unknown>;
  };
  raw.audit.path = join(root, "audit", "audit.jsonl");
  raw.approvals.stateDirectory = join(root, "approvals");
  return { config: parseConfig(raw), root };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => await fs.rm(root, { recursive: true, force: true })));
});

function transport(data: JsonValue): OperationTransport {
  return {
    execute: async (_host, operation) => ({ version: 1, requestId: operation.requestId, ok: true, data })
  };
}

describe("MCP operation service", () => {
  it("returns stable redacted envelopes and appends verifiable audit evidence", async () => {
    const { config } = await fixture();
    const service = new OperationsService(config, {
      transport: transport({ authorization: "Bearer planted-secret", url: "https://user:pass@example.test/path?token=abc" }),
      audit: new AuditLog(config.audit.path),
      clock: () => new Date("2026-01-01T00:00:00.000Z")
    });
    const result = await service.call("get_host_summary", { hostId: "demo-host" });
    assert.equal(result.ok, true);
    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes("planted-secret"));
    assert.ok(!serialized.includes("user:pass"));
    assert.ok(serialized.includes("[REDACTED]"));
    const verification = await verifyAuditLog(config.audit.path);
    assert.equal(verification.valid, true);
    assert.equal(verification.records, 2);
  });

  it("fails closed on unknown resources before SSH execution", async () => {
    const { config } = await fixture();
    let executions = 0;
    const service = new OperationsService(config, {
      transport: {
        execute: async (_host, operation) => {
          executions += 1;
          return { version: 1, requestId: operation.requestId, ok: true, data: null };
        }
      },
      audit: new AuditLog(config.audit.path)
    });
    const result = await service.call("get_service_status", { serviceId: "missing-service" });
    assert.equal(result.ok, false);
    assert.equal(executions, 0);
  });

  it("requires, verifies, and consumes exact approval before mutation", async () => {
    const { config } = await fixture();
    let executions = 0;
    const service = new OperationsService(config, {
      transport: {
        execute: async (_host, operation) => {
          executions += 1;
          return { version: 1, requestId: operation.requestId, ok: true, data: { changed: true } };
        }
      },
      audit: new AuditLog(config.audit.path),
      loadKey: async () => KEY,
      clock: () => new Date("2026-01-01T00:00:00.000Z")
    });
    const input = { serviceId: "demo-service", expectedActiveState: "active", dryRun: false };
    const required = await service.call("restart_service", input);
    assert.equal(required.ok, false);
    if (required.ok) throw new Error("approval unexpectedly not required");
    assert.equal(required.code, "APPROVAL_REQUIRED");
    const request = required.details.approvalRequest as unknown as ApprovalRequest;
    const approval = signApprovalRequest(request, KEY);
    const accepted = await service.call("restart_service", { ...input, approval });
    assert.equal(accepted.ok, true);
    assert.equal(executions, 1);
    const replay = await service.call("restart_service", { ...input, approval });
    assert.equal(replay.ok, false);
    if (!replay.ok) assert.equal(replay.code, "APPROVAL_REPLAYED");
    assert.equal(executions, 1);
  });
});
