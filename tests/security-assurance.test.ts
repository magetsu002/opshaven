import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { AuditLog } from "../src/audit.js";
import type { VerifiedCapability } from "../src/capabilities.js";
import { parseConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";
import { OperationService } from "../src/operations.js";
import { PolicyEngine } from "../src/policy.js";
import { sanitizeOutput } from "../src/redaction.js";
import { createAuthenticatedRequest, verifyAuthenticatedRequest } from "../src/remote/authenticated-protocol.js";
import { parseRemoteRequest } from "../src/remote/protocol.js";
import { FixedCommandRunner } from "../src/remote/runner.js";

async function root(): Promise<string> { return await fs.mkdtemp(path.join(tmpdir(), "opshaven-assurance-")); }
async function configFixture() {
  const base = await root();
  const config = parseConfig({
    version: 1,
    policyVersion: "assurance-v1",
    limits: { timeoutMs: 500, maxBytes: 4096, maxLines: 100 },
    audit: { path: path.join(base, "audit.jsonl") },
    approvals: { directory: path.join(base, "approvals"), secretFile: path.join(base, "secret"), signingPrivateKeyFile: path.join(base, "private.pem"), verificationPublicKeyFile: path.join(base, "public.pem"), remoteUsedDirectory: path.join(base, "remote-used"), defaultTtlSeconds: 300 },
    secretFingerprints: [],
    resources: [
      { id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: path.join(base, "known_hosts"), identityFile: path.join(base, "id_ed25519"), connectTimeoutMs: 5000 },
      { id: "svc.web", kind: "service", hostId: "host.main", unit: "web.service" },
    ],
  });
  return { base, config };
}
function protocolInvalid(action: () => unknown): boolean {
  try { action(); return false; }
  catch (error) { return error instanceof OpsHavenError && error.code === "REMOTE_PROTOCOL_INVALID"; }
}

test("deterministic malformed AI input corpus is rejected without coercion", () => {
  const malformed: unknown[] = [null, true, 0, "restart_service", [], {}, { version: 1 },
    { version: 1, requestId: "r", operation: "restart_service", resourceId: "svc.web", args: [], limits: {} },
    { version: 1, requestId: "r", operation: "restart_service;id", resourceId: "svc.web", args: { resourceId: "svc.web" }, limits: { timeoutMs: 500, maxBytes: 4096, maxLines: 100 } },
    { version: 1, requestId: "r", operation: "get_service_status", resourceId: "svc.web", args: { resourceId: "svc.web", nested: {} }, limits: { timeoutMs: 500, maxBytes: 4096, maxLines: 100 } },
    { version: 1, requestId: "r\nforged", operation: "get_service_status", resourceId: "svc.web", args: { resourceId: "svc.web" }, limits: { timeoutMs: 500, maxBytes: 4096, maxLines: 100 } }];
  let state = 0x6d2b79f5;
  for (let index = 0; index < 128; index += 1) {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    malformed.push({ version: 1, requestId: `bad/${(state >>> 0).toString(16)}`, operation: "get_service_status", resourceId: "svc.web", args: { resourceId: "svc.web" }, limits: { timeoutMs: Number.NaN, maxBytes: 4096, maxLines: 100 } });
  }
  for (const value of malformed) assert.equal(protocolInvalid(() => parseRemoteRequest(value)), true);
});

test("argument injection and path traversal remain outside policy grammar", async () => {
  const { config } = await configFixture();
  const policy = new PolicyEngine(config);
  for (const args of [{ resourceId: "svc.web", dryRun: true, command: "id" }, { resourceId: "svc.web;id", dryRun: true }, { resourceId: "../svc.web", dryRun: true }, { resourceId: "svc.web", dryRun: true, env: "PATH=/tmp" }]) assert.throws(() => policy.resolve("restart_service", args), OpsHavenError);
  assert.throws(() => parseConfig({ version: 1, policyVersion: "v1", limits: { timeoutMs: 500, maxBytes: 4096, maxLines: 100 }, audit: { path: "/var/lib/opshaven/../etc/passwd" }, approvals: { directory: "/var/lib/opshaven/approvals", secretFile: "/var/lib/opshaven/secret", signingPrivateKeyFile: "/var/lib/opshaven/private.pem", verificationPublicKeyFile: "/etc/opshaven/public.pem", remoteUsedDirectory: "/var/lib/opshaven/remote-used", defaultTtlSeconds: 300 }, secretFingerprints: [], resources: [{ id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id", connectTimeoutMs: 5000 }] }), OpsHavenError);
});

test("nonce replay and clock skew fail closed across deterministic boundary cases", async () => {
  const keys = generateKeyPairSync("ed25519");
  const privateKey = keys.privateKey.export({ type: "pkcs8", format: "pem" }) as Uint8Array;
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }) as Uint8Array;
  const capability: VerifiedCapability = { hash: "a".repeat(64), payload: { version: 1, mode: "controlled", policyVersion: "v1", allowedOperations: ["get_service_status"], allowedResources: { get_service_status: ["svc.web"] }, limits: { timeoutMs: 500, maxBytes: 4096, maxLines: 100 }, dispatcherSha256: "b".repeat(64), issuedAt: "2026-07-30T19:00:00.000Z", expiresAt: "2026-07-30T21:00:00.000Z" } };
  const request = { version: 1 as const, requestId: "assurance-request", operation: "get_service_status" as const, resourceId: "svc.web", args: { resourceId: "svc.web" }, limits: { ...capability.payload.limits } };
  const now = Date.parse("2026-07-30T20:00:00.000Z");
  const replayDirectory = path.join(await root(), "replay");
  const created = createAuthenticatedRequest(request, capability, privateKey, now, 30);
  await verifyAuthenticatedRequest(created.envelope, capability, publicKey, replayDirectory, now + 1);
  await assert.rejects(verifyAuthenticatedRequest(created.envelope, capability, publicKey, replayDirectory, now + 2));
  for (const skew of [-120000, 120000]) {
    const skewed = createAuthenticatedRequest(request, capability, privateKey, now + skew, 30);
    await assert.rejects(verifyAuthenticatedRequest(skewed.envelope, capability, publicKey, path.join(await root(), "replay"), now));
  }
});

test("oversized, slow, binary, and malicious output is bounded or rejected", async () => {
  const runner = new FixedCommandRunner();
  await assert.rejects(runner.run("/usr/bin/yes", ["A"], { timeoutMs: 1000, maxBytes: 1024, maxLines: 20 }), (error: unknown) => error instanceof OpsHavenError && error.code === "OUTPUT_LIMIT");
  await assert.rejects(runner.run("/usr/bin/sleep", ["2"], { timeoutMs: 100, maxBytes: 1024, maxLines: 20 }), (error: unknown) => error instanceof OpsHavenError && error.code === "TIMEOUT");
  assert.throws(() => sanitizeOutput("safe\u0000binary", { maxBytes: 1024, maxLines: 20 }), OpsHavenError);
  const safe = sanitizeOutput("\u001b[31mAuthorization: Bearer stolen-token\u001b[0m\napi_key=sec\u200bret-value\n", { maxBytes: 1024, maxLines: 20 });
  assert.equal(safe.text.includes("stolen-token"), false); assert.equal(safe.text.includes("secret-value"), false); assert.equal(/[\u001b\u200b]/u.test(safe.text), false);
});

test("corrupted audit state is detected after valid append", async () => {
  const file = path.join(await root(), "audit.jsonl");
  const audit = new AuditLog(file);
  await audit.append({ timestamp: "2026-07-30T20:00:00.000Z", requestId: "audit-1", actor: "assurance", operation: "get_host_summary", resourceId: "host.main", mutation: false, dryRun: false, outcome: "success", evidenceDigest: "a".repeat(64) });
  assert.equal((await audit.verify()).valid, true);
  await fs.writeFile(file, (await fs.readFile(file, "utf8")).replace("get_host_summary", "restart_service"));
  assert.equal((await audit.verify()).valid, false);
});

test("partial remote failure remains a typed failure and is audited", async () => {
  const { config } = await configFixture();
  const service = new OperationService(config, { async execute() { throw new OpsHavenError("SSH_FAILED", "Synthetic restricted transport failure.", true); } });
  const result = await service.execute("get_service_status", { resourceId: "svc.web" }, undefined, "assurance");
  assert.equal(result.ok, false); assert.equal(result.error?.code, "SSH_FAILED"); assert.equal(result.meta.auditRecorded, true);
  const verified = await service.audit.verify(); assert.equal(verified.valid, true); assert.equal(verified.records, 1);
});
