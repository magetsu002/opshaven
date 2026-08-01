import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import test from "node:test";

const root = process.cwd();

async function source(file: string): Promise<string> {
  return await fs.readFile(path.join(root, file), "utf8");
}

test("rollback is bound to the recorded previous generation rather than current desired source", async () => {
  const rollback = await source("src/setup/rollback.ts");
  assert.equal(
    rollback.includes("sourceSha: setup.expectedSourceSha"),
    false,
    "rollback must not compare historical recovery evidence with the operator's current desired source",
  );
  assert.match(rollback, /previousGenerationIdentity/);
  assert.match(rollback, /transactionId/);
});

test("authorization synchronization preserves the previous receipt before replacing live state", async () => {
  const installer = await source("packaging/remote-trust-installer.py");
  const receiptWrite = installer.indexOf("atomic_json(receipt, RECEIPT)");
  const receiptBackup = installer.indexOf("backup_existing(RECEIPT");
  assert.notEqual(receiptWrite, -1);
  assert.notEqual(receiptBackup, -1, "the previous receipt must be copied into immutable rollback evidence");
  assert.ok(receiptBackup < receiptWrite, "previous receipt evidence must be recorded before the live receipt changes");
});

test("synchronization records the previous verified generation before any remote activation", async () => {
  const engine = await source("src/setup/engine.ts");
  const recordPrevious = engine.indexOf("RECORD_PREVIOUS");
  const activate = engine.indexOf("ACTIVATE");
  assert.notEqual(recordPrevious, -1);
  assert.notEqual(activate, -1);
  assert.ok(recordPrevious < activate, "transactional rollback evidence must exist before activation");
});
