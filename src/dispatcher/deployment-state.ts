import { randomUUID } from "node:crypto";
import * as nodeFs from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { OpsHavenError } from "../core/errors.js";

type FileSystem = Pick<
  typeof nodeFs,
  "lstat" | "realpath" | "mkdir" | "readlink" | "symlink" | "rename" | "readFile" | "open" | "unlink"
>;

export type DeploymentFileSystem = FileSystem;
export const NODE_DEPLOYMENT_FILE_SYSTEM: DeploymentFileSystem = nodeFs;

export type ReleaseRecord = Readonly<{
  commit: string;
  path: string;
  activatedAt: string;
  previousCommit: string;
  migrationRisk: "none" | "manual-review";
}>;

export type DeploymentState = Readonly<{
  version: 1;
  currentCommit: string | null;
  releases: readonly ReleaseRecord[];
}>;

const COMMIT = /^[a-f0-9]{40}$/;

function isErrno(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && (error as { code?: unknown }).code === code;
}

function object(value: unknown, context: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpsHavenError("OPERATION_FAILED", `${context} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, allowed: readonly string[], context: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new OpsHavenError("OPERATION_FAILED", `${context} contains unknown fields`, { fields: unknown });
  }
}

export async function assertSafeDirectory(fs: DeploymentFileSystem, path: string, label: string): Promise<void> {
  const info = await fs.lstat(path).catch((error: unknown) => {
    throw new OpsHavenError("OPERATION_FAILED", `${label} is unavailable`, { path, reason: String(error) });
  });
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new OpsHavenError("POLICY_DENIED", `${label} must be a real directory`, { path });
  }
  const resolved = await fs.realpath(path);
  if (resolved !== path) {
    throw new OpsHavenError("POLICY_DENIED", `${label} contains a symlinked path component`, { path, resolved });
  }
}

export function isPathInside(root: string, candidate: string): boolean {
  const relation = relative(root, candidate);
  return relation !== "" && !relation.startsWith("..") && !isAbsolute(relation);
}

export async function assertPathAbsent(fs: DeploymentFileSystem, path: string, label: string): Promise<void> {
  try {
    await fs.lstat(path);
  } catch (error) {
    if (isErrno(error, "ENOENT")) return;
    throw error;
  }
  throw new OpsHavenError("POLICY_DENIED", `${label} already exists`, { path });
}

export async function readActiveRelease(
  fs: DeploymentFileSystem,
  activeSymlink: string,
  releasesPath: string
): Promise<Readonly<{ commit: string; target: string }>> {
  const info = await fs.lstat(activeSymlink).catch((error: unknown) => {
    throw new OpsHavenError("OPERATION_FAILED", "Active release link is unavailable", {
      activeSymlink,
      reason: String(error)
    });
  });
  if (!info.isSymbolicLink()) {
    throw new OpsHavenError("POLICY_DENIED", "Configured active release path must be a symbolic link");
  }
  const link = await fs.readlink(activeSymlink);
  const target = resolve(dirname(activeSymlink), link);
  if (!isPathInside(releasesPath, target)) {
    throw new OpsHavenError("POLICY_DENIED", "Active release link escapes the configured releases directory");
  }
  const commit = target.slice(target.lastIndexOf("/") + 1);
  if (!COMMIT.test(commit)) {
    throw new OpsHavenError("OPERATION_FAILED", "Active release link does not identify a recorded commit");
  }
  await assertSafeDirectory(fs, target, "Active release");
  return { commit, target };
}

export async function activateRelease(
  fs: DeploymentFileSystem,
  activeSymlink: string,
  target: string,
  releasesPath: string
): Promise<void> {
  if (!isPathInside(releasesPath, target)) {
    throw new OpsHavenError("POLICY_DENIED", "Release activation target escapes the configured releases directory");
  }
  await assertSafeDirectory(fs, target, "Release activation target");
  const temporary = `${activeSymlink}.opshaven-${randomUUID()}`;
  try {
    await fs.symlink(target, temporary);
    await fs.rename(temporary, activeSymlink);
  } finally {
    await fs.unlink(temporary).catch((error: unknown) => {
      if (!isErrno(error, "ENOENT")) throw error;
    });
  }
}

function parseRelease(value: unknown, index: number): ReleaseRecord {
  const record = object(value, `deployment state releases[${index}]`);
  exact(record, ["commit", "path", "activatedAt", "previousCommit", "migrationRisk"], `deployment state releases[${index}]`);
  if (
    typeof record.commit !== "string" ||
    !COMMIT.test(record.commit) ||
    typeof record.previousCommit !== "string" ||
    !COMMIT.test(record.previousCommit) ||
    typeof record.path !== "string" ||
    !record.path.startsWith("/") ||
    typeof record.activatedAt !== "string" ||
    Number.isNaN(Date.parse(record.activatedAt)) ||
    (record.migrationRisk !== "none" && record.migrationRisk !== "manual-review")
  ) {
    throw new OpsHavenError("OPERATION_FAILED", "Deployment state contains a malformed release record");
  }
  return {
    commit: record.commit,
    path: record.path,
    activatedAt: record.activatedAt,
    previousCommit: record.previousCommit,
    migrationRisk: record.migrationRisk
  };
}

export async function readDeploymentState(fs: DeploymentFileSystem, stateFile: string): Promise<DeploymentState> {
  let raw: string;
  try {
    const info = await fs.lstat(stateFile);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new OpsHavenError("POLICY_DENIED", "Deployment state file must be a regular file");
    }
    raw = await fs.readFile(stateFile, "utf8");
  } catch (error) {
    if (isErrno(error, "ENOENT")) return { version: 1, currentCommit: null, releases: [] };
    throw error;
  }
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw new OpsHavenError("OPERATION_FAILED", "Deployment state file is not valid JSON");
  }
  const root = object(value, "deployment state");
  exact(root, ["version", "currentCommit", "releases"], "deployment state");
  if (root.version !== 1 || (root.currentCommit !== null && (typeof root.currentCommit !== "string" || !COMMIT.test(root.currentCommit)))) {
    throw new OpsHavenError("OPERATION_FAILED", "Deployment state header is invalid");
  }
  if (!Array.isArray(root.releases)) {
    throw new OpsHavenError("OPERATION_FAILED", "Deployment state releases must be an array");
  }
  const releases = root.releases.map(parseRelease);
  const commits = new Set<string>();
  for (const release of releases) {
    if (commits.has(release.commit)) {
      throw new OpsHavenError("OPERATION_FAILED", "Deployment state contains duplicate releases");
    }
    commits.add(release.commit);
  }
  if (root.currentCommit !== null && !commits.has(root.currentCommit)) {
    throw new OpsHavenError("OPERATION_FAILED", "Deployment state current commit is not recorded");
  }
  return { version: 1, currentCommit: root.currentCommit, releases };
}

export async function writeDeploymentState(
  fs: DeploymentFileSystem,
  stateFile: string,
  state: DeploymentState
): Promise<void> {
  await assertSafeDirectory(fs, dirname(stateFile), "Deployment state directory");
  try {
    const existing = await fs.lstat(stateFile);
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new OpsHavenError("POLICY_DENIED", "Deployment state file must be a regular file");
    }
  } catch (error) {
    if (!isErrno(error, "ENOENT")) throw error;
  }
  const temporary = `${stateFile}.opshaven-${randomUUID()}`;
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(state)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, stateFile);
}
