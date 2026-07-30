import { promises as fs } from "node:fs";
import path from "node:path";
import { canonicalize, sha256 } from "./canonical.js";
import { OpsHavenError } from "./errors.js";
import { ensurePrivateDirectory, openOwnerOnlyAppendFile, readOptionalRegularTextFile } from "./safe-fs.js";

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
type Verification = { valid: true; records: number; head: string } | { valid: false; records: number; line: number; reason: string };

async function sleep(ms: number): Promise<void> { await new Promise((resolve) => setTimeout(resolve, ms)); }

function verifyText(existing: string): Verification {
  const lines = existing.split(/\r?\n/).filter(Boolean);
  let previousHash = "0".repeat(64);
  for (let index = 0; index < lines.length; index += 1) {
    let record: AuditRecord;
    try { record = JSON.parse(lines[index] as string) as AuditRecord; }
    catch { return { valid: false, records: index, line: index + 1, reason: "invalid_json" }; }
    if (!record || typeof record !== "object" || Array.isArray(record) || typeof record.hash !== "string" || !/^[a-f0-9]{64}$/.test(record.hash) || typeof record.previousHash !== "string" || !/^[a-f0-9]{64}$/.test(record.previousHash)) return { valid: false, records: index, line: index + 1, reason: "invalid_record" };
    const { hash, ...unsigned } = record;
    if (record.sequence !== index + 1) return { valid: false, records: index, line: index + 1, reason: "sequence_mismatch" };
    if (record.previousHash !== previousHash) return { valid: false, records: index, line: index + 1, reason: "chain_mismatch" };
    if (sha256(unsigned) !== hash) return { valid: false, records: index, line: index + 1, reason: "hash_mismatch" };
    previousHash = hash;
  }
  return { valid: true, records: lines.length, head: previousHash };
}

export class AuditLog {
  constructor(private readonly filePath: string) {}

  private async existing(): Promise<string> {
    return await readOptionalRegularTextFile(this.filePath, "Audit log", { ownerOnly: true, maxBytes: 16 * 1024 * 1024, code: "AUDIT_FAILED" });
  }
  private async lock<T>(work: () => Promise<T>): Promise<T> {
    await ensurePrivateDirectory(path.dirname(this.filePath), "Audit directory", "AUDIT_FAILED");
    const lockPath = `${this.filePath}.lock`;
    let handle: any;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        handle = await fs.open(lockPath, "wx", 0o600);
        break;
      } catch (error: any) {
        if (error?.code !== "EEXIST") throw new OpsHavenError("AUDIT_FAILED", "Audit log lock could not be created safely.");
        await sleep(20);
      }
    }
    if (!handle) throw new OpsHavenError("AUDIT_FAILED", "Audit log lock could not be acquired.");
    try { return await work(); }
    finally { await handle.close(); await fs.unlink(lockPath).catch(() => undefined); }
  }

  async append(event: AuditEvent): Promise<AuditRecord> {
    return await this.lock(async () => {
      const existing = await this.existing();
      const verified = verifyText(existing);
      if (!verified.valid) throw new OpsHavenError("AUDIT_FAILED", "Existing audit chain failed verification.");
      const unsigned = { ...event, sequence: verified.records + 1, previousHash: verified.head };
      const record: AuditRecord = { ...unsigned, hash: sha256(unsigned) };
      const handle = await openOwnerOnlyAppendFile(this.filePath, "Audit log", "AUDIT_FAILED");
      try { await handle.appendFile(`${canonicalize(record)}\n`, "utf8"); await handle.sync(); }
      finally { await handle.close(); }
      return record;
    });
  }

  async verify(): Promise<Verification> {
    return verifyText(await this.existing());
  }
}
