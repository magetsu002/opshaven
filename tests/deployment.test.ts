import assert from "node:assert/strict";
import test from "node:test";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { parseConfig } from "../src/config.js";
import { DeploymentManager } from "../src/remote/deployment.js";
import type { CommandRunner } from "../src/remote/runner.js";

async function fixture(withProbe = false) {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-deploy-"));
  const commit = "a".repeat(40);
  const oldCommit = "b".repeat(40);
  const resources: Record<string, unknown>[] = [
    { id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/key", connectTimeoutMs: 5000 },
    { id: "svc.web", kind: "service", hostId: "host.main", unit: "example.service" },
  ];
  if (withProbe) resources.push({ id: "probe.web", kind: "probe", hostId: "host.main", url: "http://127.0.0.1/health", method: "GET", expectedStatus: [200], timeoutMs: 1000 });
  resources.push({ id: "dep.web", kind: "deployment", hostId: "host.main", repositoryPath: path.join(root, "repository"), releasesPath: path.join(root, "releases"), currentSymlink: path.join(root, "current"), allowedRefs: ["refs/remotes/origin/main"], activation: "systemd", serviceIds: ["svc.web"], probeIds: withProbe ? ["probe.web"] : [], buildSteps: [], checkSteps: [], fetchBeforeDeploy: false, migrationPolicy: "none" });
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
    if (joined.includes("rev-parse HEAD")) return { exitCode: 0, stdout: oldCommit };
    return { exitCode: 0, stdout: commit };
  } };
  const target = config.resources.get("dep.web");
  if (!target || target.kind !== "deployment") throw new Error("missing deployment fixture");
  return { root, commit, oldCommit, config, target, runner, calls };
}

test("deployment dry-run validates without changing releases", async () => {
  const { root, commit, config, target, runner, calls } = await fixture();
  const result = await new DeploymentManager(config, runner).deploy(target, { resourceId: "dep.web", commit, dryRun: true }, config.limits);
  assert.equal(result.changed, false);
  assert.equal(await fs.stat(path.join(root, "releases")).then(() => true).catch(() => false), false);
  assert.equal(calls.some((args) => args.includes("worktree")), false);
});

test("failed deployment health verification restores prior activation", async () => {
  const { root, commit, config, target, runner } = await fixture(true);
  const previous = path.join(root, "releases", "previous");
  await fs.mkdir(previous, { recursive: true });
  await fs.symlink(previous, target.currentSymlink);
  const manager = new DeploymentManager(config, runner, async () => ({ reachable: true, statusCode: 503, latencyMs: 1, expected: false }));
  await assert.rejects(manager.deploy(target, { resourceId: "dep.web", commit, dryRun: false }, config.limits));
  assert.equal(path.resolve(path.dirname(target.currentSymlink), await fs.readlink(target.currentSymlink)), previous);
  const ledger = await fs.readFile(path.join(target.releasesPath, "opshaven-releases.jsonl"), "utf8");
  assert.ok(ledger.includes('"status":"failed"'));
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
