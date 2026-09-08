import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { OpsHavenError } from "./errors.js";
import { operatorStateRoot } from "./operator-state.js";
import { ensurePrivateDirectory, readRegularTextFile } from "./safe-fs.js";

export type TaskCategory = "primary_verification" | "development" | "advanced_maintenance" | "other";

export interface WorkspaceSourceState {
  head: string;
  clean: boolean;
  statusDigest: string;
}

export interface VerificationEvidence {
  schemaVersion: 1;
  workspaceId: string;
  taskId: string;
  taskLabel: string;
  category: TaskCategory;
  source: WorkspaceSourceState;
  sourceUnchanged: boolean;
  startedAt: string;
  finishedAt: string;
  exitCode: number | null;
  timedOut: boolean;
  cancelled: boolean;
  passed: boolean;
}
interface VerificationDocument {
  version: 1;
  runs: VerificationEvidence[];
}

const WORKSPACE_ID = /^[a-z][a-z0-9._-]{0,63}$/;
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_RUNS = 100;

export function sourceStateDigest(state: WorkspaceSourceState): string {
  return createHash("sha256").update(JSON.stringify(state)).digest("hex");
}

export function sameSourceState(a: WorkspaceSourceState, b: WorkspaceSourceState): boolean {
  return a.head === b.head && a.clean === b.clean && a.statusDigest === b.statusDigest;
}

function validSource(value: unknown): value is WorkspaceSourceState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return typeof item.head === "string" && SHA.test(item.head)
    && typeof item.clean === "boolean"
    && typeof item.statusDigest === "string" && DIGEST.test(item.statusDigest);
}
function validEvidence(value: unknown): value is VerificationEvidence {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return item.schemaVersion === 1
    && typeof item.workspaceId === "string" && WORKSPACE_ID.test(item.workspaceId)
    && typeof item.taskId === "string" && item.taskId.length > 0 && item.taskId.length <= 256
    && typeof item.taskLabel === "string" && item.taskLabel.length > 0 && item.taskLabel.length <= 512
    && ["primary_verification", "development", "advanced_maintenance", "other"].includes(String(item.category))
    && validSource(item.source)
    && typeof item.sourceUnchanged === "boolean"
    && typeof item.startedAt === "string" && Number.isFinite(Date.parse(item.startedAt))
    && typeof item.finishedAt === "string" && Number.isFinite(Date.parse(item.finishedAt))
    && (item.exitCode === null || Number.isInteger(item.exitCode))
    && typeof item.timedOut === "boolean"
    && typeof item.cancelled === "boolean"
    && typeof item.passed === "boolean";
}

export class VerificationStore {
  readonly root: string;

  constructor(stateRoot = operatorStateRoot()) {
    this.root = path.join(stateRoot, "verification");
  }

  private file(workspaceId: string): string {
    if (!WORKSPACE_ID.test(workspaceId)) throw new OpsHavenError("CONFIG_INVALID", "Workspace id is invalid.");
    return path.join(this.root, `${workspaceId}.json`);
  }

  async load(workspaceId: string): Promise<VerificationEvidence[]> {
    const file = this.file(workspaceId);
    try {
      await fs.lstat(file);
    } catch (error) {
      if ((error as { code?: string }).code === "ENOENT") return [];
      throw error;
    }
    const text = await readRegularTextFile(file, "Workspace verification evidence", {
      ownerOnly: true,
      maxBytes: MAX_BYTES,
      code: "CONFIG_INVALID",
    });
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      throw new OpsHavenError("CONFIG_INVALID", "Workspace verification evidence is malformed.");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new OpsHavenError("CONFIG_INVALID", "Workspace verification evidence is malformed.");
    }
    const document = parsed as Record<string, unknown>;
    if (document.version !== 1 || !Array.isArray(document.runs) || !document.runs.every(validEvidence)) {
      throw new OpsHavenError("CONFIG_INVALID", "Workspace verification evidence is malformed.");
    }
    return document.runs as VerificationEvidence[];
  }

  async record(evidence: VerificationEvidence): Promise<void> {
    if (!validEvidence(evidence)) throw new OpsHavenError("CONFIG_INVALID", "Workspace verification evidence is invalid.");
    await ensurePrivateDirectory(this.root, "Workspace verification directory", "CONFIG_INVALID");
    const current = await this.load(evidence.workspaceId);
    const runs = [evidence, ...current].slice(0, MAX_RUNS);
    const target = this.file(evidence.workspaceId);
    const temporary = `${target}.opshaven-${process.pid}-${Date.now()}`;
    try {
      const document: VerificationDocument = { version: 1, runs };
      await fs.writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600, flag: "wx" });
      await fs.chmod(temporary, 0o600);
      await fs.rename(temporary, target);
    } finally {
      await fs.rm(temporary, { force: true });
    }
  }

  async current(workspaceId: string, source: WorkspaceSourceState): Promise<VerificationEvidence[]> {
    return (await this.load(workspaceId)).filter((run) => run.sourceUnchanged && sameSourceState(run.source, source));
  }
}
