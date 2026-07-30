import { constants } from "node:fs";
import { appendFile, lstat, mkdir, open, readFile, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { OpsHavenError } from "../core/errors.js";
import { canonicalJson, sha256, type JsonValue } from "./canonical.js";

export type AuditOutcome = "allowed" | "denied" | "succeeded" | "failed" | "dry-run";

export type AuditEvent = Readonly<{
  requestId: string;
  operation: string;
  hostId: string;
  target: string;
  outcome: AuditOutcome;
  actor: "mcp" | "human-cli" | "dispatcher";
  evidenceDigest: string;
  details?: { readonly [key: string]: JsonValue };
}>;

export type AuditRecord = Readonly<{
  version: 1;
  sequence: number;
  timestamp: string;
  previousHash: string;
  entryHash: string;
  event: AuditEvent;
}>;

export type AuditVerification = Readonly<{
  valid: boolean;
  records: number;
  headHash: string;
  error?: string;
}>;

const GENESIS = "0".repeat(64);
const MAX_AUDIT_BYTES = 32 * 1024 * 1024;

function recordPayload(record: Omit<AuditRecord, "entryHash">): JsonValue {
  return record as unknown as JsonValue;
}

function parseRecord(line: string, lineNumber: number): AuditRecord {
  let value: unknown;
  try {
    value = JSON.parse(line) as unknown;
  } catch {
    throw new OpsHavenError("AUDIT_FAILURE", `Audit line ${lineNumber} is invalid JSON`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpsHavenError("AUDIT_FAILURE", `Audit line ${lineNumber} is not an object`);
  }
  const record = value as Record<string, unknown>;
  const fields = Object.keys(record).sort();
  if (fields.join(",") !== "entryHash,event,previousHash,sequence,timestamp,version") {
    throw new OpsHavenError("AUDIT_FAILURE", `Audit line ${lineNumber} has an invalid shape`);
  }
  if (
    record.version !== 1 ||
    !Number.isInteger(record.sequence) ||
    typeof record.timestamp !== "string" ||
    typeof record.previousHash !== "string" ||
    typeof record.entryHash !== "string" ||
    typeof record.event !== "object" ||
    record.event === null ||
    Array.isArray(record.event)
  ) {
    throw new OpsHavenError("AUDIT_FAILURE", `Audit line ${lineNumber} contains invalid fields`);
  }
  return record as AuditRecord;
}

async function readAudit(path: string): Promise<string> {
  try {
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) throw new OpsHavenError("AUDIT_FAILURE", "Audit path must not be a symlink");
    if (stats.size > MAX_AUDIT_BYTES) throw new OpsHavenError("AUDIT_FAILURE", "Audit log exceeds verification limit");
    return await readFile(path, "utf8");
  } catch (error) {
    if (error instanceof OpsHavenError) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return "";
    throw new OpsHavenError("AUDIT_FAILURE", "Unable to read audit log");
  }
}

export async function verifyAuditLog(path: string): Promise<AuditVerification> {
  try {
    const text = await readAudit(path);
    const lines = text.length === 0 ? [] : text.trimEnd().split("\n");
    let previousHash = GENESIS;
    let expectedSequence = 1;
    for (const [index, line] of lines.entries()) {
      const record = parseRecord(line, index + 1);
      if (record.sequence !== expectedSequence || record.previousHash !== previousHash) {
        throw new OpsHavenError("AUDIT_FAILURE", `Audit chain breaks at line ${index + 1}`);
      }
      const payload: Omit<AuditRecord, "entryHash"> = {
        version: 1,
        sequence: record.sequence,
        timestamp: record.timestamp,
        previousHash: record.previousHash,
        event: record.event
      };
      const expectedHash = sha256(canonicalJson(recordPayload(payload)));
      if (record.entryHash !== expectedHash) {
        throw new OpsHavenError("AUDIT_FAILURE", `Audit hash mismatch at line ${index + 1}`);
      }
      previousHash = record.entryHash;
      expectedSequence += 1;
    }
    return { valid: true, records: lines.length, headHash: previousHash };
  } catch (error) {
    return {
      valid: false,
      records: 0,
      headHash: GENESIS,
      error: error instanceof Error ? error.message : "Audit verification failed"
    };
  }
}

async function acquireLock(path: string): Promise<() => Promise<void>> {
  const lockPath = `${path}.lock`;
  let handle;
  try {
    handle = await open(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    await handle.writeFile(`${process.pid}\n`, "utf8");
    await handle.close();
  } catch {
    await handle?.close();
    throw new OpsHavenError("AUDIT_FAILURE", "Audit log is locked by another writer");
  }
  return async () => await rm(lockPath, { force: true });
}

export class AuditLog {
  readonly #path: string;
  readonly #clock: () => Date;

  public constructor(path: string, clock: () => Date = () => new Date()) {
    this.#path = path;
    this.#clock = clock;
  }

  public async append(event: AuditEvent): Promise<AuditRecord> {
    await mkdir(dirname(this.#path), { recursive: true, mode: 0o700 });
    const release = await acquireLock(this.#path);
    try {
      const verification = await verifyAuditLog(this.#path);
      if (!verification.valid) throw new OpsHavenError("AUDIT_FAILURE", verification.error ?? "Audit chain is invalid");
      const payload: Omit<AuditRecord, "entryHash"> = {
        version: 1,
        sequence: verification.records + 1,
        timestamp: this.#clock().toISOString(),
        previousHash: verification.headHash,
        event
      };
      const record: AuditRecord = {
        ...payload,
        entryHash: sha256(canonicalJson(recordPayload(payload)))
      };
      await appendFile(this.#path, `${canonicalJson(record as unknown as JsonValue)}\n`, {
        encoding: "utf8",
        mode: 0o600,
        flag: "a"
      });
      const handle = await open(this.#path, "r+");
      await handle.sync();
      await handle.close();
      return record;
    } finally {
      await release();
    }
  }
}
