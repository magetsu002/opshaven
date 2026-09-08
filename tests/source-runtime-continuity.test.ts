import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { ContinuityToolExecutor } from "../src/continuity.js";
import type { DeploymentPlanner } from "../src/deployment/planning.js";
import { WorkspaceToolExecutor } from "../src/workspace-tools.js";
import { WorkspaceStore } from "../src/workspace.js";

async function command(argv: string[], cwd: string): Promise<string> {
  const child = spawn(argv[0] as string, argv.slice(1), { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
  return await new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Uint8Array) => { stdout += Buffer.from(chunk).toString("utf8"); });
    child.stderr.on("data", (chunk: Uint8Array) => { stderr += Buffer.from(chunk).toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code: number | null) => code === 0 ? resolve(stdout.trim()) : reject(new Error(stderr || argv.join(" "))));
  });
}

function data(result: Awaited<ReturnType<ContinuityToolExecutor["execute"]>>): Record<string, any> {
  assert.equal(result.ok, true, result.error?.message);
  return result.data as Record<string, any>;
}
async function fixture() {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-continuity-"));
  const state = await fs.mkdtemp(path.join(tmpdir(), "opshaven-continuity-state-"));
  await fs.writeFile(path.join(root, "package.json"), `${JSON.stringify({
    name: "continuity-fixture",
    scripts: {
      test: "node test.mjs",
      typecheck: "node --check src.mjs",
      dev: "node src.mjs",
      "release:check": "node --check src.mjs",
      custom: "node --check src.mjs",
    },
  }, null, 2)}\n`);
  await fs.writeFile(path.join(root, "src.mjs"), "export const answer = 40;\n");
  await fs.writeFile(path.join(root, "test.mjs"), "import { answer } from './src.mjs'; if (answer < 1) process.exit(1);\n");
  await command(["git", "init", "-q"], root);
  await command(["git", "add", "."], root);
  await command(["git", "-c", "user.name=OpsHaven Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "baseline"], root);
  const deployed = await command(["git", "rev-parse", "HEAD"], root);
  await fs.writeFile(path.join(root, "src.mjs"), "export const answer = 42;\n");
  await command(["git", "add", "src.mjs"], root);
  await command(["git", "-c", "user.name=OpsHaven Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "verified change"], root);
  const head = await command(["git", "rev-parse", "HEAD"], root);
  const store = new WorkspaceStore(state);
  const registered = await store.register(root, { permissions: { read: true, edit: true, tasks: true, commands: false } });
  return { root, state, store, id: registered.id, deployed, head };
}
function plannerFixture(deployed: string, planned: string[]) {
  const app = {
    id: "sample-api",
    name: "Sample API",
    targetLabel: "synthetic",
    hostResourceId: "host.primary",
    deploymentResourceId: "deployment.sample-api",
    serviceResourceId: "service.sample-api",
    probeResourceId: "probe.sample-api",
  };
  return {
    registry: { async get(id: string) { assert.equal(id, app.id); return app; } },
    async inspect() {
      return {
        currentRevision: deployed,
        activeReleaseId: "release-current",
        sourceRepositoryRevision: planned[0] ?? deployed,
        sourceRepositoryDirty: false,
        serviceIdentifier: "sample-api.service",
        serviceActiveState: "active",
        serviceSubState: "running",
        serviceExitStatus: 0,
        healthReachable: true,
        healthExpected: true,
        healthStatusCode: 200,
        availableDiskBytes: 1024 * 1024 * 1024,
        runtimeAvailable: true,
        rollbackAvailable: true,
        targetRevisionVerified: true,
      };
    },
    async createPlan(_id: string, revision: string) {
      planned.push(revision);
      return {
        planId: `sha256:${"a".repeat(64)}`,
        plan: {
          applicationId: app.id,
          currentRevision: deployed,
          targetRevision: revision,
          observedStateFingerprint: "b".repeat(64),
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          rollback: { strategy: "restore-previous-active-release", available: true, releaseId: "release-current", revision: deployed, operations: [] },
        },
      };
    },
  } as unknown as DeploymentPlanner;
}

async function cleanup(value: { root: string; state: string }): Promise<void> {
  await Promise.all([fs.rm(value.root, { recursive: true, force: true }), fs.rm(value.state, { recursive: true, force: true })]);
}
test("V1.3 ranks tasks and binds verification to one exact source state", async () => {
  const value = await fixture();
  try {
    const planned: string[] = [];
    const workspace = new WorkspaceToolExecutor(value.store);
    const continuity = new ContinuityToolExecutor(workspace, plannerFixture(value.deployed, planned));
    const initial = data(await continuity.execute("project_state", { workspaceId: value.id }));
    assert.equal(initial.source.head, value.head);
    assert.equal(initial.source.clean, true);
    assert.deepEqual(initial.tasks.primaryVerification.map((task: any) => task.id), ["npm:test", "npm:typecheck"]);
    assert.deepEqual(initial.tasks.development.map((task: any) => task.id), ["npm:dev"]);
    assert.deepEqual(initial.tasks.advancedMaintenance.map((task: any) => task.id), ["npm:release:check"]);
    assert.deepEqual(initial.tasks.other.map((task: any) => task.id), ["npm:custom"]);
    assert.equal(initial.verification.complete, false);

    const verified = data(await continuity.execute("verify_workspace", { workspaceId: value.id, timeoutMs: 30_000 }));
    assert.equal(verified.runs.length, 2);
    assert.equal(verified.state.verification.complete, true);
    assert.deepEqual(verified.state.verification.passingPrimaryTaskIds, ["npm:test", "npm:typecheck"]);
  } finally {
    await cleanup(value);
  }
});

test("V1.3 compares local source to deployed state and prepares only current verified HEAD", async () => {
  const value = await fixture();
  try {
    const planned: string[] = [];
    const workspace = new WorkspaceToolExecutor(value.store);
    const continuity = new ContinuityToolExecutor(workspace, plannerFixture(value.deployed, planned));
    await continuity.execute("verify_workspace", { workspaceId: value.id, timeoutMs: 30_000 });

    const comparison = data(await continuity.execute("source_runtime_state", { workspaceId: value.id, applicationId: "sample-api" }));
    assert.equal(comparison.runtime.deployedRevision, value.deployed);
    assert.equal(comparison.runtime.health.expected, true);
    assert.equal(comparison.runtime.rollback.available, true);
    assert.equal(comparison.difference.kind, "local_ahead");
    assert.equal(comparison.difference.aheadBy, 1);

    const prepared = data(await continuity.execute("prepare_verified_deployment", { workspaceId: value.id, applicationId: "sample-api" }));
    assert.equal(prepared.plan.targetRevision, value.head);
    assert.deepEqual(planned, [value.head]);

    await fs.writeFile(path.join(value.root, "src.mjs"), "export const answer = 43;\n");
    const dirty = await continuity.execute("prepare_verified_deployment", { workspaceId: value.id, applicationId: "sample-api" });
    assert.equal(dirty.ok, false);
    assert.equal(dirty.error?.code, "POLICY_DENIED");
    assert.match(dirty.error?.message ?? "", /uncommitted|untracked/i);
    assert.deepEqual(planned, [value.head]);
  } finally {
    await cleanup(value);
  }
});
