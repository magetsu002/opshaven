import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { AuditLog } from "../src/audit.js";
import { ApprovalService } from "../src/approval.js";
import type { ResolvedOperation } from "../src/policy.js";

async function tempRoot(): Promise<string> { return await fs.mkdtemp(path.join(tmpdir(), "opshaven-")); }
const operation = (expectedState = "a".repeat(64), resourceId = "svc.web"): ResolvedOperation => ({ operation: "restart_service", resourceId, hostId: "host.main", args: Object.freeze({ resourceId, dryRun: false }), expectedState, policyVersion: "v1", mutation: true, dryRun: false, limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 } });

test("approval is exact and single use", async () => {
  const root = await tempRoot();
  const secretFile = path.join(root, "approval.key");
  const privateFile = path.join(root, "private.pem");
  const publicFile = path.join(root, "public.pem");
  const keys = generateKeyPairSync("ed25519");
  await fs.writeFile(secretFile, "x".repeat(64), { mode: 0o600 });
  await fs.writeFile(privateFile, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  await fs.writeFile(publicFile, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
  const service = new ApprovalService({ directory: path.join(root, "approvals"), secretFile, signingPrivateKeyFile: privateFile, verificationPublicKeyFile: publicFile, remoteUsedDirectory: path.join(root, "remote-used"), defaultTtlSeconds: 300 });
  const approved = await service.create(operation());
  await assert.rejects(service.consume(approved.token, operation("b".repeat(64))));
  await service.consume(approved.token, operation());
  await assert.rejects(service.consume(approved.token, operation()));
});

test("audit verification detects modification", async () => {
  const root = await tempRoot();
  const file = path.join(root, "audit.jsonl");
  const log = new AuditLog(file);
  await log.append({ timestamp: new Date().toISOString(), requestId: "one", actor: "test", operation: "inspect", resourceId: "host.main", mutation: false, dryRun: false, outcome: "success" });
  assert.deepEqual((await log.verify()).valid, true);
  const text = await fs.readFile(file, "utf8");
  await fs.writeFile(file, text.replace("inspect", "restart"));
  assert.deepEqual((await log.verify()).valid, false);
});
