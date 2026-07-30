import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { AuditLog, verifyAuditLog } from "../src/security/audit.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map(async (directory) => await rm(directory, { recursive: true, force: true })));
});

async function fixture(): Promise<{ directory: string; path: string; log: AuditLog }> {
  const directory = await mkdtemp(join(tmpdir(), "opshaven-audit-"));
  directories.push(directory);
  const path = join(directory, "audit.jsonl");
  return { directory, path, log: new AuditLog(path, () => new Date("2026-01-01T00:00:00.000Z")) };
}

const event = {
  requestId: "00000000-0000-4000-8000-000000000000",
  operation: "get_host_summary",
  hostId: "demo-host",
  target: "demo-host",
  outcome: "succeeded" as const,
  actor: "mcp" as const,
  evidenceDigest: "a".repeat(64)
};

describe("tamper-evident audit trail", () => {
  it("appends a verifiable hash chain", async () => {
    const { path, log } = await fixture();
    const first = await log.append(event);
    const second = await log.append({ ...event, requestId: "10000000-0000-4000-8000-000000000000" });
    assert.equal(second.previousHash, first.entryHash);
    assert.deepEqual(await verifyAuditLog(path), { valid: true, records: 2, headHash: second.entryHash });
  });

  it("detects modification and record deletion", async () => {
    const { path, log } = await fixture();
    await log.append(event);
    await log.append({ ...event, requestId: "10000000-0000-4000-8000-000000000000" });
    const lines = (await readFile(path, "utf8")).trimEnd().split("\n");
    const modified = lines[0]!.replace("succeeded", "failed");
    await writeFile(path, `${modified}\n${lines[1]}\n`);
    assert.equal((await verifyAuditLog(path)).valid, false);
    await writeFile(path, `${lines[1]}\n`);
    assert.equal((await verifyAuditLog(path)).valid, false);
  });
});
