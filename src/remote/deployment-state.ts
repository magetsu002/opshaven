import { promises as fs } from "node:fs";
import path from "node:path";
import type { DeploymentResource } from "../config.js";
import { OpsHavenError } from "../errors.js";
import type { CommandRunner, RunOptions } from "./runner.js";
import { requireSuccess } from "./runner.js";

const GIT = "/usr/bin/git";
const COMMIT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;

export interface DeploymentState {
  sourceRepositoryCommit: string;
  sourceRepositoryDirty: boolean;
  activeCommit: string | null;
  activeReleasePath: string | null;
}

export function isSafeChild(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

export async function ensureReleaseRoot(target: DeploymentResource): Promise<string> {
  await fs.mkdir(target.releasesPath, { recursive: true, mode: 0o755 });
  const stat = await fs.lstat(target.releasesPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Configured releases path must be a non-symlink directory.");
  return await fs.realpath(target.releasesPath);
}

export async function validateReleaseDirectory(target: DeploymentResource, releasePath: string): Promise<string> {
  const root = await ensureReleaseRoot(target);
  if (!isSafeChild(target.releasesPath, releasePath)) throw new OpsHavenError("POLICY_DENIED", "Release path escapes the configured releases directory.");
  const stat = await fs.lstat(releasePath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Release path must be a non-symlink directory.");
  const real = await fs.realpath(releasePath);
  if (!isSafeChild(root, real)) throw new OpsHavenError("POLICY_DENIED", "Release path resolves outside the configured releases directory.");
  return real;
}

export async function resolveCurrentRelease(target: DeploymentResource): Promise<string | null> {
  let stat: any;
  try { stat = await fs.lstat(target.currentSymlink); }
  catch (error: any) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (!stat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Configured current release path must be a symlink.");
  const value = await fs.readlink(target.currentSymlink);
  const candidate = path.resolve(path.dirname(target.currentSymlink), value);
  return await validateReleaseDirectory(target, candidate);
}

export async function readDeploymentState(target: DeploymentResource, runner: CommandRunner, limits: RunOptions): Promise<DeploymentState> {
  const sourceRepositoryCommit = await requireSuccess(runner, GIT, ["-C", target.repositoryPath, "rev-parse", "HEAD"], limits);
  if (!COMMIT.test(sourceRepositoryCommit)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Source repository returned an invalid commit ID.");
  const sourceRepositoryDirty = (await requireSuccess(runner, GIT, ["-C", target.repositoryPath, "status", "--porcelain=v1", "--untracked-files=normal"], limits)).length > 0;
  const activeReleasePath = await resolveCurrentRelease(target);
  let activeCommit: string | null = null;
  if (activeReleasePath) {
    activeCommit = await requireSuccess(runner, GIT, ["-C", activeReleasePath, "rev-parse", "HEAD"], limits);
    if (!COMMIT.test(activeCommit)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Active release returned an invalid commit ID.");
  }
  return { sourceRepositoryCommit, sourceRepositoryDirty, activeCommit, activeReleasePath };
}
