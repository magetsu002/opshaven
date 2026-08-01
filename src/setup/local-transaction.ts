import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { OpsHavenError } from "../errors.js";
import { readRegularFile } from "../safe-fs.js";
import type { RemoteSetupConfig } from "./remote.js";

export interface LocalSynchronizationSnapshot {
  readonly root: string;
  readonly entries: readonly LocalSnapshotEntry[];
}

interface LocalSnapshotEntry {
  readonly source: string;
  readonly backup: string;
  readonly present: boolean;
  readonly mode: number;
}

function errorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const value = (error as { readonly code?: unknown }).code;
  return typeof value === "string" ? value : undefined;
}

function localManagedPaths(config: RemoteSetupConfig): readonly string[] {
  return Object.freeze([
    `${config.policyConfigPath}.capability.json`,
    `${config.policyConfigPath}.declaration.json`,
    `${config.policyConfigPath}.declaration-binding.json`,
    `${config.policyConfigPath}.response-public.pem`,
    config.local.operatorPublicKeyFile,
  ]);
}

async function atomicRestore(filePath: string, bytes: Uint8Array, mode: number): Promise<void> {
  const temporary = `${filePath}.opshaven-restore-${process.pid}-${Date.now()}`;
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  try {
    await fs.writeFile(temporary, bytes, { mode });
    await fs.chmod(temporary, mode);
    await fs.rename(temporary, filePath);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

export async function snapshotLocalSynchronizationState(config: RemoteSetupConfig): Promise<LocalSynchronizationSnapshot> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-local-sync-"));
  await fs.chmod(root, 0o700);
  const entries: LocalSnapshotEntry[] = [];
  try {
    for (const [index, source] of localManagedPaths(config).entries()) {
      const backup = path.join(root, String(index));
      try {
        const stat = await fs.lstat(source);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024) throw new OpsHavenError("POLICY_DENIED", "Local synchronization state contains an unsafe file.");
        const bytes = await readRegularFile(source, "Local synchronization state", { maxBytes: 2 * 1024 * 1024, code: "POLICY_DENIED" });
        await fs.writeFile(backup, bytes, { mode: 0o600 });
        entries.push(Object.freeze({ source, backup, present: true, mode: stat.mode & 0o777 }));
      } catch (error) {
        if (errorCode(error) !== "ENOENT") throw error;
        entries.push(Object.freeze({ source, backup, present: false, mode: 0o600 }));
      }
    }
    return Object.freeze({ root, entries: Object.freeze(entries) });
  } catch (error) {
    await fs.rm(root, { recursive: true, force: true });
    throw error;
  }
}

export async function restoreLocalSynchronizationState(snapshot: LocalSynchronizationSnapshot): Promise<void> {
  for (const entry of snapshot.entries) {
    if (!entry.present) {
      try {
        const stat = await fs.lstat(entry.source);
        if (stat.isSymbolicLink() || !stat.isFile()) throw new OpsHavenError("POLICY_DENIED", "Local rollback destination is unsafe.");
        await fs.rm(entry.source, { force: true });
      } catch (error) {
        if (errorCode(error) !== "ENOENT") throw error;
      }
      continue;
    }
    const bytes = await readRegularFile(entry.backup, "Local synchronization backup", { ownerOnly: true, maxBytes: 2 * 1024 * 1024, code: "POLICY_DENIED" });
    await atomicRestore(entry.source, bytes, entry.mode);
  }
}

export async function cleanupLocalSynchronizationState(snapshot: LocalSynchronizationSnapshot | undefined): Promise<void> {
  if (snapshot) await fs.rm(snapshot.root, { recursive: true, force: true });
}
