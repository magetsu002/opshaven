import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { inspectRemoteSetupRepair, prepareReviewedCleanReinstall } from "../src/setup/repair.js";
import type { RemoteSetupConfig } from "../src/setup/remote.js";
import type { RemoteAdminTransport, SetupCommandResult } from "../src/setup/transport.js";

function result(stdout: unknown): SetupCommandResult {
  return { code: 0, stdout: typeof stdout === "string" ? stdout : JSON.stringify(stdout), stderr: "" };
}

async function fixture(): Promise<{ root: string; config: RemoteSetupConfig }> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-repair-test-"));
  const config: RemoteSetupConfig = {
    version: 1,
    policyConfigPath: path.join(root, "config.json"),
    expectedSourceSha: "1".repeat(40),
    target: { host: "example.invalid", port: 22, adminUser: "root", knownHostsFile: path.join(root, "known_hosts"), identityFile: path.join(root, "identity"), expectedHostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", privilege: "root" },
    local: { runtimeRoot: path.join(root, "dist"), dispatcherPath: path.join(root, "dist/src/remote/dispatcher.js"), wrapperTemplatePath: path.join(root, "wrapper"), capabilityDeclarationPath: path.join(root, "declaration.json"), operatorPrivateKeyFile: path.join(root, "private.pem"), operatorPublicKeyFile: path.join(root, "public.pem"), restrictedAuthorizedKeyFile: path.join(root, "restricted.pub") },
    remote: { account: "opshaven", runtimeRoot: "/usr/lib/opshaven", configPath: "/etc/opshaven/config.json", wrapperPath: "/usr/local/bin/opshaven-readonly-force-command", stateDirectory: "/var/lib/opshaven", receiptPath: "/var/lib/opshaven/setup-receipt.json", nodeCandidates: ["/usr/bin/node"] },
    trust: { expiresInSeconds: 3600 },
  };
  await fs.writeFile(config.policyConfigPath, JSON.stringify({ version: 1, policyVersion: "fixture", limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 }, audit: { path: path.join(root, "audit.jsonl") }, approvals: { directory: path.join(root, "approvals"), secretFile: path.join(root, "secret"), signingPrivateKeyFile: path.join(root, "private"), verificationPublicKeyFile: path.join(root, "public"), remoteUsedDirectory: path.join(root, "used"), defaultTtlSeconds: 300 }, secretFingerprints: [], resources: [] }), { mode: 0o600 });
  return { root, config };
}

const transaction = {
  version: 1,
  transactionId: "a".repeat(32),
  phase: "VERIFY_ACTIVE",
  changeType: "DISPATCHER_AND_AUTHORIZATION",
  hostBindingSha256: "b".repeat(64),
  desiredGenerationIdentity: "c".repeat(64),
  previousGenerationIdentity: "d".repeat(64),
  previousGenerationAvailable: true,
  snapshotRoot: `/var/lib/opshaven/transactions/${"a".repeat(32)}/previous`,
  createdAt: "2026-08-01T17:00:00.000Z",
  updatedAt: "2026-08-01T17:01:00.000Z",
  integritySha256: "e".repeat(64),
};

class QueueTransport implements RemoteAdminTransport {
  readonly scripts: string[] = [];
  constructor(private readonly queue: SetupCommandResult[]) {}
  async run(): Promise<SetupCommandResult> { throw new Error("unexpected run"); }
  async runPrivileged(): Promise<SetupCommandResult> { throw new Error("unexpected privileged run"); }
  async download(): Promise<SetupCommandResult> { throw new Error("unexpected download"); }
  async upload(): Promise<SetupCommandResult> { throw new Error("unexpected upload"); }
  async runPython(script: string): Promise<SetupCommandResult> {
    this.scripts.push(script);
    const next = this.queue.shift();
    if (!next) throw new Error("missing fixture response");
    return next;
  }
}

test("reviewed repair selects immutable previous-generation restoration", async () => {
  const value = await fixture();
  try {
    const transport = new QueueTransport([result({ status: "unresolved", transaction, integrityValid: true, hostBindingValid: true, rollbackAvailable: true, activeGenerationCertain: false, lastCompletedPhase: "VERIFY_ACTIVE" })]);
    const plan = await inspectRemoteSetupRepair(value.config, transport);
    assert.equal(plan.action, "restore-previous");
    assert.equal(plan.transactionId, transaction.transactionId);
    assert.equal(plan.previousGeneration, transaction.previousGenerationIdentity);
    assert.equal(plan.rollbackAvailable, true);
    assert.equal(plan.evidencePreserved, true);
  } finally { await fs.rm(value.root, { recursive: true, force: true }); }
});

test("invalid or unavailable rollback evidence selects preserved-evidence clean reinstall", async () => {
  const value = await fixture();
  try {
    const transport = new QueueTransport([result({ status: "invalid", transaction: null, integrityValid: false, hostBindingValid: false, rollbackAvailable: false, activeGenerationCertain: false, lastCompletedPhase: null, detail: "receipt chain invalid" })]);
    const plan = await inspectRemoteSetupRepair(value.config, transport);
    assert.equal(plan.action, "clean-reinstall-required");
    assert.equal(plan.rollbackAvailable, false);
    assert.match(plan.changes.join("; "), /evidence/i);
  } finally { await fs.rm(value.root, { recursive: true, force: true }); }
});

test("clean reinstall preparation preserves evidence before clearing fixed active state", async () => {
  const value = await fixture();
  try {
    const transport = new QueueTransport([]);
    transport.runPython = async function(script: string): Promise<SetupCommandResult> {
      this.scripts.push(script);
      if (this.scripts.length === 1) return result({ status: "invalid", transaction: null, integrityValid: false, hostBindingValid: false, rollbackAvailable: false, activeGenerationCertain: false, lastCompletedPhase: null, detail: "receipt chain invalid" });
      if (this.scripts.length === 2) {
        const requestLine = script.split("\n", 1)[0] ?? "";
        const encodedRequest = /^R=json\.loads\((.+)\)$/.exec(requestLine)?.[1];
        assert.ok(encodedRequest, "clean reinstall script must embed one canonical request");
        const request = JSON.parse(JSON.parse(encodedRequest)) as { evidenceId?: unknown };
        assert.match(String(request.evidenceId), /^[a-f0-9]{32}$/);
        const generated = String(request.evidenceId);
        return result({ ok: true, action: "clean-reinstall-prepared", evidenceId: generated, evidenceRoot: `/var/lib/opshaven/recovery-evidence/${generated}`, evidenceManifestSha256: "1".repeat(64), preserved: ["/usr/lib/opshaven", "/var/lib/opshaven/synchronization-transaction.json"], removed: ["/usr/lib/opshaven", "/var/lib/opshaven/synchronization-transaction.json"], transactionId: null, preparedAt: "2026-08-01T17:02:00.000Z" });
      }
      return result({ status: "absent", source: "installed remote state" });
    };
    const receipt = await prepareReviewedCleanReinstall(value.config, true, transport);
    assert.equal(receipt.action, "clean-reinstall-prepared");
    assert.match(receipt.evidenceRoot, /^\/var\/lib\/opshaven\/recovery-evidence\/[a-f0-9]{32}$/);
    assert.equal(receipt.evidenceManifestSha256, "1".repeat(64));
    assert.match(transport.scripts[1] ?? "", /evidence-manifest\.json/);
    const preserveIndex = (transport.scripts[1] ?? "").indexOf("evidence-manifest.json");
    const removalIndex = (transport.scripts[1] ?? "").indexOf("removed=[]");
    assert.ok(preserveIndex >= 0 && removalIndex > preserveIndex, "evidence manifest must be written before active removal");
  } finally { await fs.rm(value.root, { recursive: true, force: true }); }
});
