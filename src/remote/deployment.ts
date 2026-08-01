import { promises as fs } from "node:fs";
import path from "node:path";
import type { DeploymentResource, OpsHavenConfig, ProbeResource, ServiceResource, TrustedStep } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { openOwnerOnlyAppendFile, readOptionalRegularTextFile } from "../safe-fs.js";
import { ensureReleaseRoot, readDeploymentState, resolveCurrentRelease, validateReleaseDirectory } from "./deployment-state.js";
import { runProbe } from "./probe.js";
import type { CommandRunner, RunOptions } from "./runner.js";
import { requireSuccess } from "./runner.js";

const GIT = "/usr/bin/git";
const SYSTEMCTL = "/usr/bin/systemctl";
const SUDO = "/usr/bin/sudo";
const DOCKER = "/usr/bin/docker";
const COMMIT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
const RELEASE_ID = /^[A-Za-z0-9._-]{1,128}$/;
interface ReleaseRecord { releaseId: string; commit: string; path: string; activatedAt: string; previousPath: string | null; status: "active" | "failed" | "rolled_back"; migrationPolicy: "none" | "manual" }

async function requireDeploymentCommand(
  runner: CommandRunner,
  executable: string,
  args: readonly string[],
  options: RunOptions,
  stage: string,
): Promise<string> {
  try {
    return await requireSuccess(runner, executable, args, options);
  } catch (error) {
    if (error instanceof OpsHavenError && error.code !== "REMOTE_OPERATION_FAILED") throw error;
    throw new OpsHavenError("REMOTE_OPERATION_FAILED", `${stage} failed safely.`);
  }
}

function safeDeploymentFailure(error: unknown): string {
  return error instanceof OpsHavenError ? error.message : "Deployment transaction failed safely.";
}

function commandOptions(limits: { timeoutMs: number; maxBytes: number; maxLines: number }, cwd?: string): RunOptions { return { ...limits, ...(cwd ? { cwd } : {}) }; }
function replaceArgs(step: TrustedStep, target: DeploymentResource, releasePath: string, commit: string): string[] {
  return step.args.map((arg) => arg.replaceAll("{releasePath}", releasePath).replaceAll("{repositoryPath}", target.repositoryPath).replaceAll("{commit}", commit));
}
function validRecord(value: unknown): value is ReleaseRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return Object.keys(item).every((key) => ["releaseId", "commit", "path", "activatedAt", "previousPath", "status", "migrationPolicy"].includes(key))
    && typeof item.releaseId === "string" && RELEASE_ID.test(item.releaseId)
    && typeof item.commit === "string" && COMMIT.test(item.commit)
    && typeof item.path === "string" && path.isAbsolute(item.path)
    && typeof item.activatedAt === "string" && Number.isFinite(Date.parse(item.activatedAt))
    && (item.previousPath === null || (typeof item.previousPath === "string" && path.isAbsolute(item.previousPath)))
    && (item.status === "active" || item.status === "failed" || item.status === "rolled_back")
    && (item.migrationPolicy === "none" || item.migrationPolicy === "manual");
}

export class DeploymentManager {
  constructor(private readonly config: OpsHavenConfig, private readonly runner: CommandRunner, private readonly probeRunner: typeof runProbe = runProbe) {}

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
      for (const id of target.serviceIds) await requireDeploymentCommand(this.runner, SUDO, ["--non-interactive", SYSTEMCTL, "restart", this.service(id).unit], limits, "Approved service restart");
    } else {
      await requireDeploymentCommand(this.runner, DOCKER, ["compose", "--project-directory", releasePath, "up", "-d", "--remove-orphans"], limits, "Approved container activation");
    }
  }
  private async verifyHealth(target: DeploymentResource): Promise<void> {
    for (const id of target.probeIds) {
      const result = await this.probeRunner(this.probe(id));
      if (!result.expected) throw new OpsHavenError("REMOTE_OPERATION_FAILED", "Deployment health verification failed.");
    }
  }
  private async switchSymlink(target: DeploymentResource, releasePath: string): Promise<void> {
    const release = await validateReleaseDirectory(target, releasePath);
    const parent = path.dirname(target.currentSymlink);
    await fs.mkdir(parent, { recursive: true, mode: 0o755 });
    const parentStat = await fs.lstat(parent);
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Current release parent must be a non-symlink directory.");
    const currentStat = await fs.lstat(target.currentSymlink).catch((error: any) => error?.code === "ENOENT" ? null : Promise.reject(error));
    if (currentStat && !currentStat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Configured current release path must remain a symlink.");
    const temporary = `${target.currentSymlink}.next-${process.pid}`;
    await fs.unlink(temporary).catch((error: any) => { if (error?.code !== "ENOENT") throw error; });
    await fs.symlink(release, temporary);
    await fs.rename(temporary, target.currentSymlink);
  }
  private async clearCurrentSymlink(target: DeploymentResource): Promise<void> {
    const stat = await fs.lstat(target.currentSymlink).catch((error: any) => error?.code === "ENOENT" ? null : Promise.reject(error));
    if (!stat) return;
    if (!stat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Configured current release path is no longer a symlink.");
    await fs.unlink(target.currentSymlink);
  }
  private ledgerPath(target: DeploymentResource): string { return path.join(target.releasesPath, "opshaven-releases.jsonl"); }
  private async record(target: DeploymentResource, record: ReleaseRecord): Promise<void> {
    await ensureReleaseRoot(target);
    const handle = await openOwnerOnlyAppendFile(this.ledgerPath(target), "Release ledger", "POLICY_DENIED");
    try { await handle.appendFile(`${JSON.stringify(record)}\n`, "utf8"); await handle.sync(); }
    finally { await handle.close(); }
  }
  private async records(target: DeploymentResource): Promise<ReleaseRecord[]> {
    const text = await readOptionalRegularTextFile(this.ledgerPath(target), "Release ledger", { ownerOnly: true, maxBytes: 4 * 1024 * 1024, code: "POLICY_DENIED" });
    if (!text) return [];
    return text.split(/\r?\n/).filter(Boolean).map((line: string) => {
      let parsed: unknown;
      try { parsed = JSON.parse(line) as unknown; }
      catch { throw new OpsHavenError("POLICY_DENIED", "Release ledger contains malformed evidence."); }
      if (!validRecord(parsed)) throw new OpsHavenError("POLICY_DENIED", "Release ledger contains invalid evidence.");
      return parsed;
    });
  }
  private async restore(target: DeploymentResource, previousPath: string | null, limits: RunOptions): Promise<void> {
    if (!previousPath) {
      await this.clearCurrentSymlink(target);
      return;
    }
    await this.switchSymlink(target, previousPath);
    await this.activate(target, previousPath, limits);
    await this.verifyHealth(target);
  }

  async deploy(target: DeploymentResource, args: Readonly<Record<string, string | number | boolean>>, limitsInput: { timeoutMs: number; maxBytes: number; maxLines: number }): Promise<Record<string, unknown>> {
    const commit = String(args.commit);
    const dryRun = args.dryRun === true;
    const limits = commandOptions(limitsInput);
    const state = await readDeploymentState(target, this.runner, limits);
    if (state.sourceRepositoryDirty) throw new OpsHavenError("POLICY_DENIED", "Deployment source repository is dirty.");
    if (typeof args.expectedCurrentCommit === "string" && state.activeCommit?.toLowerCase() !== args.expectedCurrentCommit.toLowerCase()) throw new OpsHavenError("POLICY_DENIED", "Active deployed commit no longer matches the expected state.");
    if (target.fetchBeforeDeploy && !dryRun) await requireSuccess(this.runner, GIT, ["-C", target.repositoryPath, "fetch", "--prune", "--tags"], limits);
    const exactCommit = await this.verifyCommit(target, commit, limits);
    const releaseId = `release-${exactCommit.slice(0, 12)}-${Date.now()}`;
    const releasePath = path.join(target.releasesPath, releaseId);
    const previousPath = state.activeReleasePath;
    const plan = { releaseId, commit: exactCommit, currentCommit: state.activeCommit, previousPath, activation: target.activation, services: target.serviceIds, probes: target.probeIds, migrationPolicy: target.migrationPolicy, migrationWarning: "Database migrations are never run or reversed automatically." };
    if (dryRun) return { dryRun: true, changed: false, plan };
    await ensureReleaseRoot(target);
    await requireDeploymentCommand(this.runner, GIT, ["-C", target.repositoryPath, "worktree", "add", "--detach", releasePath, exactCommit], limits, "Deployment release preparation");
    await validateReleaseDirectory(target, releasePath);
    try {
      const reviewedSteps = [...target.buildSteps, ...target.checkSteps];
    for (const [index, step] of reviewedSteps.entries()) {
      await requireDeploymentCommand(
        this.runner,
        step.executable,
        replaceArgs(step, target, releasePath, exactCommit),
        commandOptions(limitsInput, step.cwd === "release" ? releasePath : target.repositoryPath),
        `Deployment reviewed build or check step ${index + 1}`,
      );
    }
      await this.switchSymlink(target, releasePath);
      await this.activate(target, releasePath, limits);
      await this.verifyHealth(target);
      await this.record(target, { releaseId, commit: exactCommit, path: releasePath, activatedAt: new Date().toISOString(), previousPath, status: "active", migrationPolicy: target.migrationPolicy });
      return { dryRun: false, changed: true, releaseId, commit: exactCommit, previousCommit: state.activeCommit, previousPath, healthVerified: true, migrationPolicy: target.migrationPolicy, migrationWarning: "Database migrations were not changed automatically." };
    } catch (error) {
      try { await this.restore(target, previousPath, limits); }
      catch { throw new OpsHavenError("REMOTE_OPERATION_FAILED", `${safeDeploymentFailure(error)} Prior activation restoration failed safely.`); }
      await this.record(target, { releaseId, commit: exactCommit, path: releasePath, activatedAt: new Date().toISOString(), previousPath, status: "failed", migrationPolicy: target.migrationPolicy }).catch(() => undefined);
      throw error;
    }
  }

  async rollback(target: DeploymentResource, args: Readonly<Record<string, string | number | boolean>>, limitsInput: { timeoutMs: number; maxBytes: number; maxLines: number }): Promise<Record<string, unknown>> {
    const releaseId = String(args.releaseId);
    const dryRun = args.dryRun === true;
    const records = await this.records(target);
    const record = [...records].reverse().find((item) => item.releaseId === releaseId && item.status === "active");
    if (!record) throw new OpsHavenError("POLICY_DENIED", "Rollback target is not a known recorded release.");
    const targetPath = await validateReleaseDirectory(target, record.path);
    const limits = commandOptions(limitsInput);
    const commit = await requireSuccess(this.runner, GIT, ["-C", targetPath, "rev-parse", "HEAD"], limits);
    if (commit.toLowerCase() !== record.commit.toLowerCase()) throw new OpsHavenError("POLICY_DENIED", "Recorded release commit does not match its evidence.");
    const previousPath = await resolveCurrentRelease(target);
    if (dryRun) return { dryRun: true, changed: false, plan: { releaseId, commit, previousPath, targetPath, migrationWarning: "Database migrations are never reversed automatically." } };
    try {
      await this.switchSymlink(target, targetPath);
      await this.activate(target, targetPath, limits);
      await this.verifyHealth(target);
      await this.record(target, { ...record, path: targetPath, activatedAt: new Date().toISOString(), previousPath, status: "rolled_back" });
      return { dryRun: false, changed: true, releaseId, commit, healthVerified: true, migrationWarning: "Database migrations were not reversed." };
    } catch (error) {
      try { await this.restore(target, previousPath, limits); }
      catch { throw new OpsHavenError("REMOTE_OPERATION_FAILED", "Rollback failed and the prior activation could not be restored safely."); }
      throw error;
    }
  }
}
