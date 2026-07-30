import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { ApprovalService } from "../src/approval.js";
import { parseConfig, loadConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";
import { OperationService } from "../src/operations.js";
import type { ResolvedOperation } from "../src/policy.js";
import { verifyAndConsumeRemoteAuthorization } from "../src/remote/authorization.js";
import { dispatch } from "../src/remote/dispatcher.js";
import { FixedCommandRunner } from "../src/remote/runner.js";
import type { RemoteRequest } from "../src/remote/protocol.js";

async function root(): Promise<string> { return await fs.mkdtemp(path.join(tmpdir(), "opshaven-adversarial-")); }
async function approvalFixture() {
  const base = await root();
  const keys = generateKeyPairSync("ed25519");
  const secretFile = path.join(base, "secret");
  const privateFile = path.join(base, "private.pem");
  const publicFile = path.join(base, "public.pem");
  await fs.writeFile(secretFile, "s".repeat(64), { mode: 0o600 });
  await fs.writeFile(privateFile, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  await fs.writeFile(publicFile, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
  const config = parseConfig({ version: 1, policyVersion: "v1", limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 }, audit: { path: path.join(base, "audit.jsonl") }, approvals: { directory: path.join(base, "approvals"), secretFile, signingPrivateKeyFile: privateFile, verificationPublicKeyFile: publicFile, remoteUsedDirectory: path.join(base, "remote-used"), defaultTtlSeconds: 300 }, secretFingerprints: [], resources: [
    { id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id", connectTimeoutMs: 5000 },
    { id: "svc.web", kind: "service", hostId: "host.main", unit: "web.service" },
    { id: "svc.other", kind: "service", hostId: "host.main", unit: "other.service" },
  ] });
  return { base, config };
}

test("remote approval rejects argument mutation and replay", async () => {
  const { config } = await approvalFixture();
  const state = "a".repeat(64);
  const resolved: ResolvedOperation = { operation: "restart_service", resourceId: "svc.web", hostId: "host.main", args: { resourceId: "svc.web", dryRun: false }, expectedState: state, policyVersion: "v1", mutation: true, dryRun: false, limits: config.limits };
  const local = new ApprovalService(config.approvals);
  const token = await local.create(resolved);
  const consumed = await local.consume(token.token, resolved);
  const baseRequest: RemoteRequest = { version: 1, requestId: "r1", operation: "restart_service", resourceId: "svc.web", args: resolved.args, limits: config.limits, authorization: consumed.authorization };
  await assert.rejects(verifyAndConsumeRemoteAuthorization(config, { ...baseRequest, resourceId: "svc.other", args: { resourceId: "svc.other", dryRun: false } }, consumed.authorization, state));
  await verifyAndConsumeRemoteAuthorization(config, baseRequest, consumed.authorization, state);
  await assert.rejects(verifyAndConsumeRemoteAuthorization(config, baseRequest, consumed.authorization, state), (error: unknown) => error instanceof OpsHavenError && error.code === "APPROVAL_REPLAYED");
});

test("forced dispatcher rejects any original SSH command", async () => {
  const response = await dispatch(["node", "dispatcher.js", "--config", "/unused"], "id");
  assert.equal(response.ok, false);
  if (!response.ok) assert.equal(response.error.code, "POLICY_DENIED");
});

test("configuration symlinks fail closed", async () => {
  const base = await root();
  const real = path.join(base, "real.json");
  const link = path.join(base, "link.json");
  await fs.writeFile(real, "{}");
  await fs.symlink(real, link);
  await assert.rejects(loadConfig(link), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
});

test("fixed command runner kills output exhaustion", async () => {
  await assert.rejects(new FixedCommandRunner().run("/usr/bin/printf", ["%0200d", "1"], { timeoutMs: 1000, maxBytes: 16, maxLines: 2 }), (error: unknown) => error instanceof OpsHavenError && error.code === "OUTPUT_LIMIT");
});

test("structured remote secrets are redacted before MCP output", async () => {
  const { base, config } = await approvalFixture();
  const service = new OperationService(config, { async execute(_host, request) { return { version: 1, requestId: request.requestId, ok: true, data: { header: "Authorization: Bearer planted-secret-token" }, evidence: { startedAt: "s", finishedAt: "f", truncated: false, redactions: 0 } }; } });
  const result = await service.execute("get_service_status", { resourceId: "svc.web" });
  assert.equal(JSON.stringify(result).includes("planted-secret-token"), false);
  assert.equal((await fs.stat(path.join(base, "audit.jsonl"))).isFile(), true);
});
