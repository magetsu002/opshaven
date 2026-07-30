import { promises as fs } from "node:fs";
import path from "node:path";
import type { DeploymentResource, OpsHavenConfig, ProbeResource, ServiceResource, TrustedStep } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { runProbe } from "./probe.js";
import type { CommandRunner, RunOptions } from "./runner.js";
import { requireSuccess } from "./runner.js";

const GIT = "/usr/bin/git";
const SYSTEMCTL = "/usr/bin/systemctl";
const SUDO = "/usr/bin/sudo";
const DOCKER = "/usr/bin/docker";
interface ReleaseRecord { releaseId: string; commit: string; path: string; activatedAt: string; previousPath: string | null; status: "active" | "failed" | "rolled_back"; migrationPolicy: "none" | "manual" }

function safeChild(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}
function commandOptions(limits: { timeoutMs: number; maxBytes: number; maxLines: number }, cwd?: string): RunOptions { return { ...limits, ...(cwd ? { cwd } : {}) }; }
function replaceArgs(step: TrustedStep, target: DeploymentResource, releasePath: string, commit: string): string[] {
  return step.args.map((arg) => arg.replaceAll("{releasePath}", releasePath).replaceAll("{repositoryPath}", target.repositoryPath).replaceAll("{commit}", commit));
}

export class DeploymentManager {
  constructor(private readonly config: OpsHavenConfig, private readonly runner: CommandRunner, private readonly probeRunner: typeof runProbe = runProbe) {}

  private async repositoryState(target: DeploymentResource, limits: RunOptions): Promise<{ commit: string; dirty: boolean }> {
    const commit = await requireSuccess(this.runner, GIT, ["-C", target.repositoryPath, "rev-parse", "HEAD"], limits);
    const dirty = (await requireSuccess(this.runner, GIT, ["-C", target.repositoryPath, "status", "--porcelain=v1", "--untracked-files=normal"], limits)).length > 0;
    return { commit, dirty };
  }
  private async verifyCommit(target: DeploymentResource, commit: string, limits: RunOptions): Promise<string> {
    const resolved = await requireSuccess(this.runner, GIT, ["-C", target.repositoryPath, "rev-parse", "--verify", `${commit}^{commit}`], limits);
    if (resolved.toLowerCase() !== commit.toLowerCase()) throw new OpsHavenError("POLICY_DENIED", "Requested commit did not resolve exactly.");
    let allowed = false;
    for (const ref of target.allowedRefs) {
      const result = await this.runner.run(GIT, ["-C", target.repositoryPath, "merge-base", "--is-ancestor", resolved, ref], limits);
      if (result.exitCode === 0) { allowed = true; break; }
    }
    if (!allowed) throw new OpsHavenError("POLICY_DENIED", "Requested commit is outside configured allowed refs.");
    return resolved;
  }
  private service(id: string): ServiceResource {
    const item = this.config.resources.get(id);
    if (!item || item.kind !== "service") throw new OpsHavenError("CONFIG_INVALID", "Deployment references an invalid service.");
    return item;
  }
  private probe(id: string): ProbeResource {
    const item = this.config.resources.get(id);
    if (!item || item.kind !== "probe") throw new OpsHavenError("CONFIG_INVALID", "Deployment references an invalid probe.");
    return item;
  }
  private async activate(target: DeploymentResource, releasePath: string, limits: RunOptions): Promise<void> {
    if (target.activation === "systemd") {
      for (const id of target.serviceIds) await requireSuccess(this.runner, SUDO, ["--non-interactive", SYSTEMCTL, "restart", this.service(id).unit], limits);
    } else {
      await requireSuccess(this.runner, DOCKER, ["compose", "--project-directory", releasePath, "up", "-d", "--remove-orphans"], limits);
    }
  }
  private async verifyHealth(target: DeploymentResource): Promise<void> {
    for (const id of target.probeIds) {
      const result = await this.probeRunner(this.probe(id));
      if (!result.expected) throw new OpsHavenError("REMOTE_OPERATION_FAILED", "Deployment health verification failed.");
    }
  }
  private async currentTarget(target: DeploymentResource): Promise<string | null> {
    try {
      const stat = await fs.lstat(target.currentSymlink);
      if (!stat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Configured current release path must be a symlink.");
      const value = await fs.readlink(target.currentSymlink);
      const absolute = path.resolve(path.dirname(target.currentSymlink), value);
      if (!safeChild(target.releasesPath, absolute)) throw new OpsHavenError("POLICY_DENIED", "Current release symlink escapes the releases directory.");
      return absolute;
    } catch (error: any) {
      if (error?.code === "ENOENT") return null;
      throw error;
    }
  }
  private async switchSymlink(target: DeploymentResource, releasePath: string): Promise<void> {
    if (!safeChild(target.releasesPath, releasePath)) throw new OpsHavenError("POLICY_DENIED", "Release path escapes configured releases directory.");
    await fs.mkdir(path.dirname(target.currentSymlink), { recursive: true, mode: 0o755 });
    const temporary = `${target.currentSymlink}.next-${process.pid}`;
    await fs.unlink(temporary).catch(() => undefined);
    await fs.symlink(releasePath, temporary);
    await fs.rename(temporary, target.currentSymlink);
  }
  private ledgerPath(target: DeploymentResource): string { return path.join(target.releasesPath, "opshaven-releases.jsonl"); }
  private async record(target: DeploymentResource, record: ReleaseRecord): Promise<void> {
    await fs.mkdir(target.releasesPath, { recursive: true, mode: 0o755 });
    const ledger = this.ledgerPath(target);
    const stat = await fs.lstat(ledger).catch((error: any) => error?.code === "ENOENT" ? null : Promise.reject(error));
    if (stat?.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Release ledger cannot be a symlink.");
    const handle = await fs.open(ledger, "a", 0o600);
    try { await handle.appendFile(`${JSON.stringify(record)}\n`, "utf8"); await handle.sync(); }
    finally { await handle.close(); }
  }
  private async records(target: DeploymentResource): Promise<ReleaseRecord[]> {
    const text = await fs.readFile(this.ledgerPath(target), "utf8").catch((error: any) => error?.code === "ENOENT" ? "" : Promise.reject(error));
    return text.split(/\r?\n/).filter(Boolean).map((line: string) => JSON.parse(line) as ReleaseRecord);
  }

  async deploy(target: DeploymentResource, args: Readonly<Record<string, string | number | boolean>>, limitsInput: { timeoutMs: number; maxBytes: number; maxLines: number }): Promise<Record<string, unknown>> {
    const commit = String(args.commit);
    const dryRun = args.dryRun === true;
    const limits = commandOptions(limitsInput);
    const state = await this.repositoryState(target, limits);
    if (state.dirty) throw new OpsHavenError("POLICY_DENIED", "Deployment repository is dirty.");
    if (typeof args.expectedCurrentCommit === "string" && state.commit !== args.expectedCurrentCommit) throw new OpsHavenError("POLICY_DENIED", "Current commit no longer matches the expected state.");
    if (target.fetchBeforeDeploy && !dryRun) await requireSuccess(this.runner, GIT, ["-C", target.repositoryPath, "fetch", "--prune", "--tags"], limits);
    const exactCommit = await this.verifyCommit(target, commit, limits);
    const releaseId = `release-${exactCommit.slice(0, 12)}-${Date.now()}`;
    const releasePath = path.join(target.releasesPath, releaseId);
    const previousPath = await this.currentTarget(target);
    const plan = { releaseId, commit: exactCommit, previousPath, activation: target.activation, services: target.serviceIds, probes: target.probeIds, migrationPolicy: target.migrationPolicy, migrationWarning: "Database migrations are never run or reversed automatically." };
    if (dryRun) return { dryRun: true, changed: false, plan };
    if (!safeChild(target.releasesPath, releasePath)) throw new OpsHavenError("POLICY_DENIED", "Generated release path is unsafe.");
    await fs.mkdir(target.releasesPath, { recursive: true, mode: 0o755 });
    await requireSuccess(this.runner, GIT, ["-C", target.repositoryPath, "worktree", "add", "--detach", releasePath, exactCommit], limits);
    try {
      for (const step of [...target.buildSteps, ...target.checkSteps]) await requireSuccess(this.runner, step.executable, replaceArgs(step, target, releasePath, exactCommit), commandOptions(limitsInput, step.cwd === "release" ? releasePath : target.repositoryPath));
      await this.switchSymlink(target, releasePath);
      await this.activate(target, releasePath, limits);
      await this.verifyHealth(target);
      await this.record(target, { releaseId, commit: exactCommit, path: releasePath, activatedAt: new Date().toISOString(), previousPath, status: "active", migrationPolicy: target.migrationPolicy });
      return { dryRun: false, changed: true, releaseId, commit: exactCommit, previousPath, healthVerified: true, migrationPolicy: target.migrationPolicy, migrationWarning: "Database migrations were not changed automatically." };
    } catch (error) {
      if (previousPath) {
        await this.switchSymlink(target, previousPath);
        await this.activate(target, previousPath, limits).catch(() => undefined);
      }
      await this.record(target, { releaseId, commit: exactCommit, path: releasePath, activatedAt: new Date().toISOString(), previousPath, status: "failed", migrationPolicy: target.migrationPolicy }).catch(() => undefined);
      throw error;
    }
  }

  async rollback(target: DeploymentResource, args: Readonly<Record<string, string | number | boolean>>, limitsInput: { timeoutMs: number; maxBytes: number; maxLines: number }): Promise<Record<string, unknown>> {
    const releaseId = String(args.releaseId);
    const dryRun = args.dryRun === true;
    const records = await this.records(target);
    const record = [...records].reverse().find((item) => item.releaseId === releaseId && item.status === "active");
    if (!record || !safeChild(target.releasesPath, record.path)) throw new OpsHavenError("POLICY_DENIED", "Rollback target is not a known recorded release.");
    const stat = await fs.lstat(record.path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Recorded release path is invalid.");
    const limits = commandOptions(limitsInput);
    const commit = await requireSuccess(this.runner, GIT, ["-C", record.path, "rev-parse", "HEAD"], limits);
    if (commit !== record.commit) throw new OpsHavenError("POLICY_DENIED", "Recorded release commit does not match its evidence.");
    const previousPath = await this.currentTarget(target);
    if (dryRun) return { dryRun: true, changed: false, plan: { releaseId, commit, previousPath, targetPath: record.path, migrationWarning: "Database migrations are never reversed automatically." } };
    try {
      await this.switchSymlink(target, record.path);
      await this.activate(target, record.path, limits);
      await this.verifyHealth(target);
      await this.record(target, { ...record, activatedAt: new Date().toISOString(), previousPath, status: "rolled_back" });
      return { dryRun: false, changed: true, releaseId, commit, healthVerified: true, migrationWarning: "Database migrations were not reversed." };
    } catch (error) {
      if (previousPath) { await this.switchSymlink(target, previousPath); await this.activate(target, previousPath, limits).catch(() => undefined); }
      throw error;
    }
  }
}
