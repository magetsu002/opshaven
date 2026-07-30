import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { AuditLog } from "../src/audit.js";
import { ApprovalService, decodeApprovalPayload } from "../src/approval.js";
import { OpsHavenError } from "../src/errors.js";
import type { ResolvedOperation } from "../src/policy.js";

async function tempRoot(): Promise<string> { return await fs.mkdtemp(path.join(tmpdir(), "opshaven-")); }
const operation = (expectedState = "a".repeat(64), resourceId = "svc.web"): ResolvedOperation => ({ operation: "restart_service", resourceId, hostId: "host.main", args: Object.freeze({ resourceId, dryRun: false }), expectedState, policyVersion: "v1", mutation: true, dryRun: false, limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 } });

async function approvalFixture(root: string) {
  const secretFile = path.join(root, "approval.key");
  const privateFile = path.join(root, "private.pem");
  const publicFile = path.join(root, "public.pem");
  const keys = generateKeyPairSync("ed25519");
  await fs.writeFile(secretFile, "x".repeat(64), { mode: 0o600 });
  await fs.writeFile(privateFile, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  await fs.writeFile(publicFile, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
  const config = { directory: path.join(root, "approvals"), secretFile, signingPrivateKeyFile: privateFile, verificationPublicKeyFile: publicFile, remoteUsedDirectory: path.join(root, "remote-used"), defaultTtlSeconds: 300 };
  return { config, service: new ApprovalService(config) };
}

test("approval is exact and single use", async () => {
  const root = await tempRoot();
  const { service } = await approvalFixture(root);
  const approved = await service.create(operation());
  await assert.rejects(service.consume(approved.token, operation("b".repeat(64))));
  await service.consume(approved.token, operation());
  await assert.rejects(service.consume(approved.token, operation()));
});

test("approval rejects symlinked state directories and modified pending evidence", async () => {
  const root = await tempRoot();
  const { config, service } = await approvalFixture(root);
  const realDirectory = path.join(root, "real-approvals");
  await fs.mkdir(realDirectory, { mode: 0o700 });
  await fs.symlink(realDirectory, config.directory);
  await assert.rejects(service.create(operation()), (error: unknown) => error instanceof OpsHavenError && error.code === "APPROVAL_INVALID");
  await fs.unlink(config.directory);
  const approved = await service.create(operation());
  const body = decodeApprovalPayload(approved.token.split(".")[0] as string);
  await fs.writeFile(path.join(config.directory, "pending", body.nonce), "{}", { mode: 0o600 });
  await assert.rejects(service.consume(approved.token, operation()), (error: unknown) => error instanceof OpsHavenError && error.code === "APPROVAL_INVALID");
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
  await assert.rejects(log.append({ timestamp: new Date().toISOString(), requestId: "two", actor: "test", operation: "inspect", resourceId: "host.main", mutation: false, dryRun: false, outcome: "success" }), (error: unknown) => error instanceof OpsHavenError && error.code === "AUDIT_FAILED");
});

test("audit rejects a symlinked log path", async () => {
  const root = await tempRoot();
  const real = path.join(root, "real-audit.jsonl");
  const link = path.join(root, "audit.jsonl");
  await fs.writeFile(real, "", { mode: 0o600 });
  await fs.symlink(real, link);
  const log = new AuditLog(link);
  await assert.rejects(log.verify(), (error: unknown) => error instanceof OpsHavenError && error.code === "AUDIT_FAILED");
  await assert.rejects(log.append({ timestamp: new Date().toISOString(), requestId: "one", actor: "test", operation: "inspect", resourceId: "host.main", mutation: false, dryRun: false, outcome: "success" }), (error: unknown) => error instanceof OpsHavenError && error.code === "AUDIT_FAILED");
});
