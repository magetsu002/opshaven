import assert from "node:assert/strict";
import test from "node:test";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { parseConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";
import { readDeploymentState } from "../src/remote/deployment-state.js";
import { DeploymentManager } from "../src/remote/deployment.js";
import type { CommandRunner } from "../src/remote/runner.js";

async function fixture(withProbe = false) {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-deploy-"));
  const commit = "a".repeat(40);
  const sourceCommit = "b".repeat(40);
  const activeCommit = "c".repeat(40);
  const repositoryPath = path.join(root, "repository");
  const resources: Record<string, unknown>[] = [
    { id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/key", connectTimeoutMs: 5000 },
    { id: "svc.web", kind: "service", hostId: "host.main", unit: "example.service" },
  ];
  if (withProbe) resources.push({ id: "probe.web", kind: "probe", hostId: "host.main", url: "http://127.0.0.1/health", method: "GET", expectedStatus: [200], timeoutMs: 1000 });
  resources.push({ id: "dep.web", kind: "deployment", hostId: "host.main", repositoryPath, releasesPath: path.join(root, "releases"), currentSymlink: path.join(root, "current"), allowedRefs: ["refs/remotes/origin/main"], activation: "systemd", serviceIds: ["svc.web"], probeIds: withProbe ? ["probe.web"] : [], buildSteps: [], checkSteps: [], fetchBeforeDeploy: false, migrationPolicy: "none" });
  const config = parseConfig({ version: 1, policyVersion: "v1", limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 }, audit: { path: path.join(root, "audit.jsonl") }, approvals: { directory: path.join(root, "approvals"), secretFile: path.join(root, "secret"), signingPrivateKeyFile: path.join(root, "private.pem"), verificationPublicKeyFile: path.join(root, "public.pem"), remoteUsedDirectory: path.join(root, "remote-used"), defaultTtlSeconds: 300 }, secretFingerprints: [], resources });
  const calls: string[][] = [];
  const runner: CommandRunner = { async run(_executable, args) {
    calls.push([...args]);
    const joined = args.join(" ");
    if (joined.includes("status --porcelain")) return { exitCode: 0, stdout: "" };
    if (joined.includes("merge-base --is-ancestor")) return { exitCode: 0, stdout: "" };
    if (args.includes("worktree")) {
      await fs.mkdir(args.at(-2) as string, { recursive: true });
      return { exitCode: 0, stdout: "" };
    }
    if (joined.includes("rev-parse --verify")) return { exitCode: 0, stdout: commit };
    if (joined.includes("rev-parse HEAD")) return { exitCode: 0, stdout: args[1] === repositoryPath ? sourceCommit : activeCommit };
    return { exitCode: 0, stdout: "" };
  } };
  const target = config.resources.get("dep.web");
  if (!target || target.kind !== "deployment") throw new Error("missing deployment fixture");
  return { root, commit, sourceCommit, activeCommit, config, target, runner, calls };
}

async function installCurrent(root: string, currentSymlink: string, name = "previous"): Promise<string> {
  const previous = path.join(root, "releases", name);
  await fs.mkdir(previous, { recursive: true });
  await fs.symlink(previous, currentSymlink);
  return previous;
}

test("deployment dry-run validates without changing releases", async () => {
  const { root, commit, config, target, runner, calls } = await fixture();
  const result = await new DeploymentManager(config, runner).deploy(target, { resourceId: "dep.web", commit, dryRun: true }, config.limits);
  assert.equal(result.changed, false);
  assert.equal((result.plan as Record<string, unknown>).currentCommit, null);
  assert.equal(await fs.stat(path.join(root, "releases")).then(() => true).catch(() => false), false);
  assert.equal(calls.some((args) => args.includes("worktree")), false);
});

test("expected current commit is checked against the active release, not source checkout", async () => {
  const { root, commit, sourceCommit, activeCommit, config, target, runner } = await fixture();
  await installCurrent(root, target.currentSymlink);
  const state = await readDeploymentState(target, runner, config.limits);
  assert.equal(state.sourceRepositoryCommit, sourceCommit);
  assert.equal(state.activeCommit, activeCommit);
  const planned = await new DeploymentManager(config, runner).deploy(target, { resourceId: "dep.web", commit, expectedCurrentCommit: activeCommit, dryRun: true }, config.limits);
  assert.equal((planned.plan as Record<string, unknown>).currentCommit, activeCommit);
  await assert.rejects(new DeploymentManager(config, runner).deploy(target, { resourceId: "dep.web", commit, expectedCurrentCommit: sourceCommit, dryRun: true }, config.limits), (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED");
});

test("deployment activates the exact requested commit", async () => {
  const { root, commit, config, target, runner } = await fixture(true);
  const previous = await installCurrent(root, target.currentSymlink);
  const manager = new DeploymentManager(config, runner, async () => ({ reachable: true, statusCode: 200, latencyMs: 1, expected: true }));
  const result = await manager.deploy(target, { resourceId: "dep.web", commit, dryRun: false }, config.limits);
  assert.equal(result.commit, commit);
  assert.equal(result.previousPath, previous);
  const current = path.resolve(path.dirname(target.currentSymlink), await fs.readlink(target.currentSymlink));
  assert.notEqual(current, previous);
  assert.ok(path.basename(current).startsWith(`release-${commit.slice(0, 12)}-`));
});

test("failed deployment health verification restores prior activation", async () => {
  const { root, commit, config, target, runner } = await fixture(true);
  const previous = await installCurrent(root, target.currentSymlink);
  let probes = 0;
  const manager = new DeploymentManager(config, runner, async () => {
    probes += 1;
    return probes === 1 ? { reachable: true, statusCode: 503, latencyMs: 1, expected: false } : { reachable: true, statusCode: 200, latencyMs: 1, expected: true };
  });
  await assert.rejects(manager.deploy(target, { resourceId: "dep.web", commit, dryRun: false }, config.limits));
  assert.equal(path.resolve(path.dirname(target.currentSymlink), await fs.readlink(target.currentSymlink)), previous);
  const ledger = await fs.readFile(path.join(target.releasesPath, "opshaven-releases.jsonl"), "utf8");
  assert.ok(ledger.includes('"status":"failed"'));
});

test("current release cannot escape through a nested symlink", async () => {
  const { root, config, target, runner } = await fixture();
  const outside = path.join(root, "outside");
  await fs.mkdir(path.join(root, "releases"), { recursive: true });
  await fs.mkdir(outside);
  await fs.symlink(outside, path.join(root, "releases", "escape"));
  await fs.symlink(path.join(root, "releases", "escape"), target.currentSymlink);
  await assert.rejects(readDeploymentState(target, runner, config.limits), (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED");
});

test("manual rollback activates only a recorded release", async () => {
  const { root, commit, config, target } = await fixture(true);
  const current = path.join(root, "releases", "current-release");
  const recorded = path.join(root, "releases", "recorded-release");
  await fs.mkdir(current, { recursive: true });
  await fs.mkdir(recorded, { recursive: true });
  await fs.symlink(current, target.currentSymlink);
  await fs.writeFile(path.join(target.releasesPath, "opshaven-releases.jsonl"), `${JSON.stringify({ releaseId: "release-known", commit, path: recorded, activatedAt: new Date().toISOString(), previousPath: null, status: "active", migrationPolicy: "none" })}\n`);
  const runner: CommandRunner = { async run(_executable, args) {
    if (args.includes("rev-parse")) return { exitCode: 0, stdout: commit };
    return { exitCode: 0, stdout: "" };
  } };
  const manager = new DeploymentManager(config, runner, async () => ({ reachable: true, statusCode: 200, latencyMs: 1, expected: true }));
  const result = await manager.rollback(target, { resourceId: "dep.web", releaseId: "release-known", dryRun: false }, config.limits);
  assert.equal(result.changed, true);
  assert.equal(path.resolve(path.dirname(target.currentSymlink), await fs.readlink(target.currentSymlink)), recorded);
});
