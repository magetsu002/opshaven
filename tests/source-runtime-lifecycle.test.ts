import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { ContinuityToolExecutor } from "../src/continuity.js";
import { loadConfig, parseConfig } from "../src/config.js";
import { DeploymentCoordinator, type OperationClient } from "../src/deployment.js";
import type { ResultEnvelope } from "../src/operations.js";
import { WorkspaceToolExecutor } from "../src/workspace-tools.js";
import { WorkspaceStore } from "../src/workspace.js";

function success(operation: string, data: Record<string, unknown>, mutation = false): ResultEnvelope {
  const now = new Date(0).toISOString();
  return { ok: true, requestId: `req-${operation}`, operation, data, meta: { startedAt: now, finishedAt: now, dryRun: !mutation, mutation, truncated: false, redactions: 0, auditRecorded: true } };
}

async function command(argv: string[], cwd: string): Promise<string> {
  const child = spawn(argv[0] as string, argv.slice(1), { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
  return await new Promise((resolve, reject) => {
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (chunk: Uint8Array) => { stdout += Buffer.from(chunk).toString("utf8"); });
    child.stderr.on("data", (chunk: Uint8Array) => { stderr += Buffer.from(chunk).toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code: number | null) => code === 0 ? resolve(stdout.trim()) : reject(new Error(stderr || argv.join(" "))));
  });
}
class SyntheticRuntime implements OperationClient {
  currentRevision: string;
  sourceRevision: string;
  previousRevision: string;
  activeReleaseId = "release-current";
  healthy = true;
  failHealthAfterDeploy = false;

  constructor(currentRevision: string, sourceRevision: string) {
    this.currentRevision = currentRevision;
    this.sourceRevision = sourceRevision;
    this.previousRevision = currentRevision;
  }

  async execute(operation: string, raw: unknown): Promise<ResultEnvelope> {
    const args = raw as Record<string, unknown>;
    if (operation === "get_deployed_commit") return success(operation, { activeCommit: this.currentRevision, activeReleaseId: this.activeReleaseId, sourceRepositoryCommit: this.sourceRevision, dirty: false });
    if (operation === "get_service_status") return success(operation, { unit: "sample-api.service", activeState: "active", subState: "running", exitStatus: 0 });
    if (operation === "run_health_probe") return success(operation, { reachable: true, expected: this.healthy, statusCode: this.healthy ? 200 : 503 });
    if (operation === "get_host_summary") return success(operation, { uname: "Linux synthetic", rootFilesystem: "/dev/synthetic 20000000 1000 10000000 1% /" });
    if (operation === "deploy_commit" && args.dryRun === true) return success(operation, { changed: false, plan: { commit: args.commit } });
    if (operation === "deploy_commit") {
      assert.equal(args.expectedCurrentCommit, this.currentRevision);
      this.previousRevision = this.currentRevision;
      this.currentRevision = String(args.commit);
      this.activeReleaseId = `release-${this.currentRevision.slice(0, 12)}`;
      if (this.failHealthAfterDeploy) this.healthy = false;
      return success(operation, { changed: true, commit: this.currentRevision }, true);
    }
    if (operation === "rollback_deployment") {
      this.currentRevision = this.previousRevision;
      this.activeReleaseId = `release-${this.currentRevision.slice(0, 12)}`;
      this.healthy = true;
      this.failHealthAfterDeploy = false;
      return success(operation, { changed: true, commit: this.currentRevision }, true);
    }
    throw new Error(`Unsupported operation ${operation}`);
  }

  async createApproval(): Promise<{ token: string; digest: string; expiresAt: string; operationDigest: string }> {
    return { token: "synthetic-approval", digest: "a".repeat(64), expiresAt: new Date(Date.now() + 60_000).toISOString(), operationDigest: "b".repeat(64) };
  }
}

async function localRepository(): Promise<{ root: string; baseline: string; target: string }> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-lifecycle-workspace-"));
  await fs.writeFile(path.join(root, "package.json"), `${JSON.stringify({ name: "sample-api", scripts: { test: "node test.mjs", typecheck: "node --check app.mjs" } }, null, 2)}\n`);
  await fs.writeFile(path.join(root, "app.mjs"), "export const version = 1;\n");
  await fs.writeFile(path.join(root, "test.mjs"), "import { version } from './app.mjs'; if (version < 1) process.exit(1);\n");
  await command(["git", "init", "-q"], root);
  await command(["git", "add", "."], root);
  await command(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "baseline"], root);
  const baseline = await command(["git", "rev-parse", "HEAD"], root);
  await fs.writeFile(path.join(root, "app.mjs"), "export const version = 2;\n");
  await command(["git", "add", "app.mjs"], root);
  await command(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "target"], root);
  return { root, baseline, target: await command(["git", "rev-parse", "HEAD"], root) };
}
async function coordinatorFixture(root: string, client: SyntheticRuntime) {
  const configPath = path.join(root, "config.json");
  const stateRoot = path.join(root, "deployment-state");
  const knownHosts = path.join(root, "known_hosts");
  const identity = path.join(root, "restricted-ssh");
  const publicKey = path.join(root, "operator-public.pem");
  const privateKey = path.join(root, "operator-private.pem");
  const approvalSecret = path.join(root, "approval-secret");
  await fs.writeFile(knownHosts, "example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISynthetic\n", { mode: 0o600 });
  await fs.writeFile(identity, "synthetic-private-identity\n", { mode: 0o600 });
  await fs.writeFile(publicKey, "synthetic-public-verification-key\n", { mode: 0o600 });
  await fs.writeFile(privateKey, "synthetic-private-signing-key\n", { mode: 0o600 });
  await fs.writeFile(approvalSecret, "synthetic-approval-secret-32-bytes!!\n", { mode: 0o600 });
  const document = {
    version: 1,
    policyVersion: "v1",
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    audit: { path: path.join(root, "audit.jsonl") },
    approvals: { directory: path.join(root, "approvals"), secretFile: approvalSecret, signingPrivateKeyFile: privateKey, verificationPublicKeyFile: publicKey, remoteUsedDirectory: path.join(root, "remote-used"), defaultTtlSeconds: 300 },
    secretFingerprints: [],
    resources: [{ id: "host.primary", kind: "host", address: "example.invalid", port: 22, user: "opshaven", knownHostsFile: knownHosts, identityFile: identity, connectTimeoutMs: 5000 }],
  };
  parseConfig(document);
  await fs.writeFile(configPath, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600 });
  await fs.writeFile(`${configPath}.dispatcher.json`, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600 });
  let coordinator = new DeploymentCoordinator(await loadConfig(configPath), configPath, { root: stateRoot, client, nonce: () => "c".repeat(32) });
  await coordinator.registerApplication({
    id: "sample-api",
    name: "Sample API",
    remoteTarget: "host.primary",
    repositoryLocation: path.join(root, "remote", "repository"),
    releaseLocation: path.join(root, "remote", "releases"),
    serviceIdentifier: "sample-api.service",
    healthCheckUrl: "http://127.0.0.1:3000/health",
  });
  coordinator = new DeploymentCoordinator(await loadConfig(configPath), configPath, { root: stateRoot, client, nonce: () => "c".repeat(32) });
  return coordinator;
}

function data(result: Awaited<ReturnType<ContinuityToolExecutor["execute"]>>): Record<string, any> {
  assert.equal(result.ok, true, result.error?.message);
  return result.data as Record<string, any>;
}

test("disposable V1.3 lifecycle verifies, compares, deploys, checks health, and preserves rollback", async () => {
  const repository = await localRepository();
  const state = await fs.mkdtemp(path.join(tmpdir(), "opshaven-lifecycle-state-"));
  const operator = await fs.mkdtemp(path.join(tmpdir(), "opshaven-lifecycle-operator-"));
  try {
    const runtime = new SyntheticRuntime(repository.baseline, repository.target);
    const coordinator = await coordinatorFixture(operator, runtime);
    const store = new WorkspaceStore(state);
    const registered = await store.register(repository.root, { permissions: { read: true, edit: true, tasks: true, commands: false } });
    const workspace = new WorkspaceToolExecutor(store);
    const continuity = new ContinuityToolExecutor(workspace, coordinator);
    const verified = data(await continuity.execute("verify_workspace", { workspaceId: registered.id, timeoutMs: 30_000 }));
    assert.equal(verified.state.verification.complete, true);

    const before = data(await continuity.execute("source_runtime_state", { workspaceId: registered.id, applicationId: "sample-api" }));
    assert.equal(before.workspace.source.head, repository.target);
    assert.equal(before.runtime.deployedRevision, repository.baseline);
    assert.equal(before.difference.kind, "local_ahead");
    assert.equal(before.runtime.health.expected, true);

    const prepared = data(await continuity.execute("prepare_verified_deployment", { workspaceId: registered.id, applicationId: "sample-api" }));
    assert.equal(prepared.plan.targetRevision, repository.target);
    const applied = await coordinator.applyPlan(prepared.plan.planId, { approved: true });
    assert.equal(applied.outcome, "DEPLOYMENT_SUCCEEDED");
    assert.equal(applied.activeRevision, repository.target);
    assert.equal(applied.healthVerified, true);

    const after = data(await continuity.execute("source_runtime_state", { workspaceId: registered.id, applicationId: "sample-api" }));
    assert.equal(after.difference.kind, "match");
    assert.equal(after.runtime.rollback.available, true);
    await fs.writeFile(path.join(repository.root, "app.mjs"), "export const version = 3;\n");
    await command(["git", "add", "app.mjs"], repository.root);
    await command(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "next target"], repository.root);
    const nextTarget = await command(["git", "rev-parse", "HEAD"], repository.root);
    runtime.sourceRevision = nextTarget;
    data(await continuity.execute("verify_workspace", { workspaceId: registered.id, timeoutMs: 30_000 }));
    const recoveryPlan = data(await continuity.execute("prepare_verified_deployment", { workspaceId: registered.id, applicationId: "sample-api" }));
    runtime.failHealthAfterDeploy = true;
    const recovered = await coordinator.applyPlan(recoveryPlan.plan.planId, { approved: true });
    assert.equal(recovered.outcome, "DEPLOYMENT_FAILED_ROLLED_BACK");
    assert.equal(recovered.activeRevision, repository.target);
    assert.equal(recovered.rollbackAttempted, true);
    assert.equal(recovered.healthVerified, true);

    const recoveredState = data(await continuity.execute("source_runtime_state", { workspaceId: registered.id, applicationId: "sample-api" }));
    assert.equal(recoveredState.runtime.deployedRevision, repository.target);
    assert.equal(recoveredState.difference.kind, "local_ahead");
    assert.equal(recoveredState.runtime.health.expected, true);
  } finally {
    await Promise.all([
      fs.rm(repository.root, { recursive: true, force: true }),
      fs.rm(state, { recursive: true, force: true }),
      fs.rm(operator, { recursive: true, force: true }),
    ]);
  }
});
