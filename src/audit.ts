import { promises as fs } from "node:fs";
import path from "node:path";
import { canonicalize, sha256 } from "./canonical.js";
import { OpsHavenError } from "./errors.js";

export interface AuditEvent {
  timestamp: string;
  requestId: string;
  actor: string;
  operation: string;
  resourceId: string;
  mutation: boolean;
  dryRun: boolean;
  approvalDigest?: string;
  outcome: "success" | "denied" | "failure";
  errorCode?: string;
  evidenceDigest?: string;
}
interface AuditRecord extends AuditEvent { sequence: number; previousHash: string; hash: string }

async function sleep(ms: number): Promise<void> { await new Promise((resolve) => setTimeout(resolve, ms)); }

export class AuditLog {
  constructor(private readonly filePath: string) {}

  private async lock<T>(work: () => Promise<T>): Promise<T> {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    const lockPath = `${this.filePath}.lock`;
    let handle: any;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        handle = await fs.open(lockPath, "wx", 0o600);
        break;
      } catch (error: any) {
        if (error?.code !== "EEXIST") throw error;
        await sleep(20);
      }
    }
    if (!handle) throw new OpsHavenError("AUDIT_FAILED", "Audit log lock could not be acquired.");
    try { return await work(); }
    finally { await handle.close(); await fs.unlink(lockPath).catch(() => undefined); }
  }

  async append(event: AuditEvent): Promise<AuditRecord> {
    return await this.lock(async () => {
      const existing = await fs.readFile(this.filePath, "utf8").catch((error: any) => error?.code === "ENOENT" ? "" : Promise.reject(error));
      const lines = existing.split(/\r?\n/).filter(Boolean);
      let previousHash = "0".repeat(64);
      let sequence = 1;
      if (lines.length > 0) {
        const previous = JSON.parse(lines.at(-1) as string) as AuditRecord;
        previousHash = previous.hash;
        sequence = previous.sequence + 1;
      }
      const unsigned = { ...event, sequence, previousHash };
      const record: AuditRecord = { ...unsigned, hash: sha256(unsigned) };
      const handle = await fs.open(this.filePath, "a", 0o600);
      try { await handle.appendFile(`${canonicalize(record)}\n`, "utf8"); await handle.sync(); }
      finally { await handle.close(); }
      return record;
    });
  }

  async verify(): Promise<{ valid: true; records: number; head: string } | { valid: false; records: number; line: number; reason: string }> {
    const existing = await fs.readFile(this.filePath, "utf8").catch((error: any) => error?.code === "ENOENT" ? "" : Promise.reject(error));
    const lines = existing.split(/\r?\n/).filter(Boolean);
    let previousHash = "0".repeat(64);
    for (let index = 0; index < lines.length; index += 1) {
      let record: AuditRecord;
      try { record = JSON.parse(lines[index] as string) as AuditRecord; }
      catch { return { valid: false, records: index, line: index + 1, reason: "invalid_json" }; }
      const { hash, ...unsigned } = record;
      if (record.sequence !== index + 1) return { valid: false, records: index, line: index + 1, reason: "sequence_mismatch" };
      if (record.previousHash !== previousHash) return { valid: false, records: index, line: index + 1, reason: "chain_mismatch" };
      if (sha256(unsigned) !== hash) return { valid: false, records: index, line: index + 1, reason: "hash_mismatch" };
      previousHash = hash;
    }
    return { valid: true, records: lines.length, head: previousHash };
  }
}
