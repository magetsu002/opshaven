import { constants, promises as fs } from "node:fs";
import type { ErrorCode } from "./errors.js";
import { OpsHavenError } from "./errors.js";

interface FilePolicy {
  ownerOnly?: boolean;
  maxBytes?: number;
  code?: ErrorCode;
}

function failure(label: string, policy: FilePolicy): OpsHavenError {
  return new OpsHavenError(policy.code ?? "POLICY_DENIED", `${label} must be a safe regular non-symlink file.`);
}

function validateStat(stat: any, label: string, policy: FilePolicy): void {
  if (!stat.isFile() || stat.isSymbolicLink?.() || (policy.ownerOnly === true && (stat.mode & 0o077) !== 0) || (policy.maxBytes !== undefined && stat.size > policy.maxBytes)) throw failure(label, policy);
}

async function openReadOnly(filePath: string, label: string, policy: FilePolicy): Promise<any> {
  let before: any;
  try { before = await fs.lstat(filePath); }
  catch { throw failure(label, policy); }
  validateStat(before, label, policy);
  let handle: any;
  try { handle = await fs.open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); }
  catch { throw failure(label, policy); }
  try {
    const after = await handle.stat();
    validateStat(after, label, policy);
    if (before.dev !== after.dev || before.ino !== after.ino) throw failure(label, policy);
    return handle;
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

export async function verifyRegularFile(filePath: string, label: string, policy: FilePolicy = {}): Promise<void> {
  const handle = await openReadOnly(filePath, label, policy);
  await handle.close();
}

export async function readRegularFile(filePath: string, label: string, policy: FilePolicy = {}): Promise<Uint8Array> {
  const handle = await openReadOnly(filePath, label, policy);
  try { return await handle.readFile(); }
  finally { await handle.close(); }
}

export async function readRegularTextFile(filePath: string, label: string, policy: FilePolicy = {}): Promise<string> {
  return Buffer.from(await readRegularFile(filePath, label, policy)).toString("utf8");
}

export async function readOptionalRegularTextFile(filePath: string, label: string, policy: FilePolicy = {}): Promise<string> {
  try { await fs.lstat(filePath); }
  catch (error: any) {
    if (error?.code === "ENOENT") return "";
    throw failure(label, policy);
  }
  return await readRegularTextFile(filePath, label, policy);
}

export async function ensurePrivateDirectory(directoryPath: string, label: string, code: ErrorCode = "POLICY_DENIED"): Promise<void> {
  await fs.mkdir(directoryPath, { recursive: true, mode: 0o700 });
  let stat: any;
  try { stat = await fs.lstat(directoryPath); }
  catch { throw new OpsHavenError(code, `${label} must be a private non-symlink directory.`); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) throw new OpsHavenError(code, `${label} must be a private non-symlink directory.`);
}

export async function openOwnerOnlyAppendFile(filePath: string, label: string, code: ErrorCode = "AUDIT_FAILED"): Promise<any> {
  let before: any = null;
  try { before = await fs.lstat(filePath); }
  catch (error: any) {
    if (error?.code !== "ENOENT") throw new OpsHavenError(code, `${label} is not a safe append-only file.`);
  }
  if (before && (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o077) !== 0)) throw new OpsHavenError(code, `${label} is not a safe append-only file.`);
  let handle: any;
  try { handle = await fs.open(filePath, constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600); }
  catch { throw new OpsHavenError(code, `${label} could not be opened safely.`); }
  try {
    const after = await handle.stat();
    if (!after.isFile() || (after.mode & 0o077) !== 0 || (before && (before.dev !== after.dev || before.ino !== after.ino))) throw new OpsHavenError(code, `${label} changed during validation.`);
    return handle;
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}
