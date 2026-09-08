import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { asOpsHavenError, OpsHavenError } from "./errors.js";
import type { ResultEnvelope } from "./operations.js";
import { detectWorkspaceProject, WorkspaceStore, type WorkspaceRecord } from "./workspace.js";

const DEFAULT_MAX_BYTES = 128 * 1024;
const MAX_TOOL_BYTES = 1024 * 1024;
const MAX_EDIT_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;
const MAX_SEARCH_FILES = 5000;
const SKIP_DIRECTORIES = new Set([".git", "node_modules", "vendor", "dist", "build", "target", ".next", "coverage", ".venv", "venv", "__pycache__", ".cache"]);
const LOCAL_TOOL_NAMES = new Set([
  "workspace_info", "workspace_tree", "list_files", "read_file", "read_files", "search_files", "file_hash", "code_context",
  "git_status", "git_diff", "git_log", "project_info", "discover_tasks",
  "create_file", "replace_file", "edit_file", "edit_files", "run_task", "run_command",
]);

function schema(properties: Record<string, unknown>, required: string[] = []): Record<string, unknown> {
  return { type: "object", additionalProperties: false, properties, required };
}
const workspaceId = { type: "string", pattern: "^[a-z][a-z0-9._-]{0,63}$" };
const relativePath = { type: "string", minLength: 1, maxLength: 4096, description: "Path relative to the workspace root." };
const expectedHash = { type: "string", pattern: "^[a-f0-9]{64}$", description: "SHA-256 identity returned by a prior read/hash." };
const timeout = { type: "integer", minimum: 100, maximum: MAX_TIMEOUT_MS, default: DEFAULT_TIMEOUT_MS };
const maxBytes = { type: "integer", minimum: 1024, maximum: MAX_TOOL_BYTES, default: DEFAULT_MAX_BYTES };

export const WORKSPACE_TOOL_DEFINITIONS = [
  { name: "workspace_info", description: "Return workspace root, permissions, and detected project metadata.", inputSchema: schema({ workspaceId }, ["workspaceId"]) },
  { name: "workspace_tree", description: "Return a bounded project tree while skipping common generated and vendor directories.", inputSchema: schema({ workspaceId, path: { ...relativePath, default: "." }, depth: { type: "integer", minimum: 1, maximum: 8, default: 4 }, maxEntries: { type: "integer", minimum: 1, maximum: 2000, default: 400 } }, ["workspaceId"]) },
  { name: "list_files", description: "List one workspace directory as structured entries.", inputSchema: schema({ workspaceId, path: { ...relativePath, default: "." }, maxEntries: { type: "integer", minimum: 1, maximum: 1000, default: 250 } }, ["workspaceId"]) },
  { name: "read_file", description: "Read one bounded UTF-8 project file and return its SHA-256 identity.", inputSchema: schema({ workspaceId, path: relativePath, maxBytes }, ["workspaceId", "path"]) },
  { name: "read_files", description: "Read up to 20 bounded UTF-8 project files in one call.", inputSchema: schema({ workspaceId, paths: { type: "array", minItems: 1, maxItems: 20, items: relativePath }, maxBytesEach: { type: "integer", minimum: 1024, maximum: 512 * 1024, default: 128 * 1024 } }, ["workspaceId", "paths"]) },
  { name: "search_files", description: "Search bounded project text without scanning common generated and vendor directories.", inputSchema: schema({ workspaceId, query: { type: "string", minLength: 1, maxLength: 256 }, path: { ...relativePath, default: "." }, maxResults: { type: "integer", minimum: 1, maximum: 200, default: 50 } }, ["workspaceId", "query"]) },
  { name: "file_hash", description: "Return the SHA-256 identity and size of one project file.", inputSchema: schema({ workspaceId, path: relativePath }, ["workspaceId", "path"]) },
  { name: "code_context", description: "Return a bounded line range with line numbers and current file identity.", inputSchema: schema({ workspaceId, path: relativePath, startLine: { type: "integer", minimum: 1, maximum: 1_000_000, default: 1 }, endLine: { type: "integer", minimum: 1, maximum: 1_000_000 }, contextLines: { type: "integer", minimum: 0, maximum: 50, default: 5 } }, ["workspaceId", "path"]) },
  { name: "git_status", description: "Return structured Git working-tree status for the workspace.", inputSchema: schema({ workspaceId }, ["workspaceId"]) },
  { name: "git_diff", description: "Return a bounded Git diff for the workspace or one project path.", inputSchema: schema({ workspaceId, staged: { type: "boolean", default: false }, path: relativePath, maxBytes }, ["workspaceId"]) },
  { name: "git_log", description: "Return a structured bounded Git commit log.", inputSchema: schema({ workspaceId, maxCount: { type: "integer", minimum: 1, maximum: 50, default: 10 } }, ["workspaceId"]) },
  { name: "project_info", description: "Refresh and return detected project ecosystems and manifests.", inputSchema: schema({ workspaceId }, ["workspaceId"]) },
  { name: "discover_tasks", description: "Discover runnable tasks only from project metadata and recognized ecosystem conventions.", inputSchema: schema({ workspaceId }, ["workspaceId"]) },
  { name: "create_file", description: "Create a new project file without overwriting an existing path.", inputSchema: schema({ workspaceId, path: relativePath, content: { type: "string", maxLength: MAX_EDIT_BYTES } }, ["workspaceId", "path", "content"]) },
  { name: "replace_file", description: "Atomically replace a project file only if its current SHA-256 matches expectedHash.", inputSchema: schema({ workspaceId, path: relativePath, content: { type: "string", maxLength: MAX_EDIT_BYTES }, expectedHash }, ["workspaceId", "path", "content", "expectedHash"]) },
  { name: "edit_file", description: "Apply one exact targeted text replacement with optimistic concurrency.", inputSchema: schema({ workspaceId, path: relativePath, oldText: { type: "string", minLength: 1, maxLength: MAX_EDIT_BYTES }, newText: { type: "string", maxLength: MAX_EDIT_BYTES }, expectedHash }, ["workspaceId", "path", "oldText", "newText", "expectedHash"]) },
  { name: "edit_files", description: "Preflight and apply exact optimistic-concurrency edits across multiple files.", inputSchema: schema({ workspaceId, edits: { type: "array", minItems: 1, maxItems: 20, items: { type: "object", additionalProperties: false, properties: { path: relativePath, oldText: { type: "string", minLength: 1, maxLength: MAX_EDIT_BYTES }, newText: { type: "string", maxLength: MAX_EDIT_BYTES }, expectedHash }, required: ["path", "oldText", "newText", "expectedHash"] } }, ["workspaceId", "edits"]) },
  { name: "run_task", description: "Run one task discovered from project metadata when task execution is enabled.", inputSchema: schema({ workspaceId, taskId: { type: "string", minLength: 1, maxLength: 256 }, args: { type: "array", maxItems: 32, items: { type: "string", maxLength: 512 } }, cwd: relativePath, timeoutMs: timeout, maxBytes }, ["workspaceId", "taskId"]) },
  { name: "run_command", description: "Run one argv-based local command in the workspace when broader command execution is enabled. Privilege escalation is blocked.", inputSchema: schema({ workspaceId, argv: { type: "array", minItems: 1, maxItems: 64, items: { type: "string", maxLength: 4096 } }, cwd: relativePath, timeoutMs: timeout, maxBytes }, ["workspaceId", "argv"]) },
] as const;

export interface DiscoveredTask {
  id: string;
  label: string;
  argv: string[];
  source: string;
}

interface ProcessResult {
  argv: string[];
  cwd: string;
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  cancelled: boolean;
  truncated: boolean;
}

function argsObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("INVALID_ARGUMENTS", "Tool arguments must be an object.");
  return value as Record<string, unknown>;
}
function stringValue(value: unknown, label: string, maximum = 4096): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.includes("\0")) throw new OpsHavenError("INVALID_ARGUMENTS", `${label} is invalid.`);
  return value;
}
function integerValue(value: unknown, fallback: number, minimum: number, maximum: number, label: string): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) throw new OpsHavenError("INVALID_ARGUMENTS", `${label} is invalid.`);
  return value as number;
}
function booleanValue(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new OpsHavenError("INVALID_ARGUMENTS", `${label} is invalid.`);
  return value;
}
function workspaceArg(args: Record<string, unknown>): string { return stringValue(args.workspaceId, "workspaceId", 64); }
function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function requestId(): string { return randomBytes(12).toString("hex"); }
function inside(root: string, candidate: string): boolean { return candidate === root || candidate.startsWith(`${root}${path.sep}`); }

function relative(value: unknown, fallback = "."): string {
  const source = value === undefined ? fallback : stringValue(value, "path");
  if (path.isAbsolute(source) || source.includes("\\")) throw new OpsHavenError("INVALID_ARGUMENTS", "Project paths must be relative to the workspace.");
  const normalized = path.normalize(source);
  if (normalized === ".." || normalized.startsWith(`..${path.sep}`)) throw new OpsHavenError("POLICY_DENIED", "Project path escapes the workspace.");
  return normalized === "" ? "." : normalized;
}

async function assertNoSymlinkComponents(workspace: WorkspaceRecord, relativePath: string, includeFinal = true): Promise<string> {
  const clean = relative(relativePath);
  const candidate = path.resolve(workspace.root, clean);
  if (!inside(workspace.root, candidate)) throw new OpsHavenError("POLICY_DENIED", "Project path escapes the workspace.");
  const parts = clean === "." ? [] : clean.split(path.sep).filter(Boolean);
  let current = workspace.root;
  const limit = includeFinal ? parts.length : Math.max(0, parts.length - 1);
  for (let index = 0; index < limit; index += 1) {
    current = path.join(current, parts[index] as string);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Symlink traversal inside a workspace is not allowed.");
    } catch (error) {
      if ((error as any)?.code === "ENOENT") break;
      throw error;
    }
  }
  return candidate;
}

async function existingPath(workspace: WorkspaceRecord, value: unknown, kind: "file" | "directory"): Promise<{ relative: string; absolute: string; stat: any }> {
  const clean = relative(value);
  const absolute = await assertNoSymlinkComponents(workspace, clean, true);
  let stat: any;
  try { stat = await fs.lstat(absolute); }
  catch { throw new OpsHavenError("INVALID_ARGUMENTS", `Project ${kind} does not exist.`); }
  if (stat.isSymbolicLink() || (kind === "file" ? !stat.isFile() : !stat.isDirectory())) throw new OpsHavenError("POLICY_DENIED", `Project ${kind} is unsafe or has the wrong type.`);
  const real = await fs.realpath(absolute);
  if (!inside(workspace.root, real)) throw new OpsHavenError("POLICY_DENIED", "Resolved project path escapes the workspace.");
  return { relative: clean, absolute, stat };
}

async function writeTarget(workspace: WorkspaceRecord, value: unknown): Promise<{ relative: string; absolute: string; parent: string }> {
  const clean = relative(value);
  if (clean === ".") throw new OpsHavenError("INVALID_ARGUMENTS", "A file path is required.");
  const absolute = await assertNoSymlinkComponents(workspace, clean, false);
  const parent = path.dirname(absolute);
  const parentRelative = path.relative(workspace.root, parent) || ".";
  await existingPath(workspace, parentRelative, "directory");
  return { relative: clean, absolute, parent };
}

function requirePermission(workspace: WorkspaceRecord, permission: keyof WorkspaceRecord["permissions"]): void {
  if (!workspace.permissions[permission]) throw new OpsHavenError("POLICY_DENIED", `Workspace permission "${permission}" is disabled.`, false, { workspaceId: workspace.id, permission });
}

async function readText(workspace: WorkspaceRecord, file: unknown, maximum: number): Promise<{ path: string; text: string; hash: string; bytes: number; mode: number }> {
  const target = await existingPath(workspace, file, "file");
  if (target.stat.size > maximum) throw new OpsHavenError("OUTPUT_LIMIT", "Project file exceeds the requested read bound.", false, { bytes: target.stat.size, maxBytes: maximum });
  const text = await fs.readFile(target.absolute, "utf8");
  if (text.includes("\0")) throw new OpsHavenError("BINARY_OUTPUT", "Binary project files are not returned as text.");
  return { path: target.relative, text, hash: digest(text), bytes: Buffer.byteLength(text, "utf8"), mode: target.stat.mode & 0o777 };
}

async function atomicReplace(target: string, content: string, mode: number): Promise<void> {
  if (Buffer.byteLength(content, "utf8") > MAX_EDIT_BYTES) throw new OpsHavenError("OUTPUT_LIMIT", "Edited file exceeds the V1.2 edit bound.");
  const temporary = `${target}.opshaven-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  try {
    await fs.writeFile(temporary, content, { mode, flag: "wx" });
    await fs.chmod(temporary, mode);
    await fs.rename(temporary, target);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

async function walk(root: string, start: string, maximumEntries: number, maximumDepth: number): Promise<Array<{ path: string; type: "file" | "directory" }>> {
  const output: Array<{ path: string; type: "file" | "directory" }> = [];
  async function visit(directory: string, depth: number): Promise<void> {
    if (output.length >= maximumEntries || depth > maximumDepth) return;
    const entries = await fs.readdir(directory, { withFileTypes: true });
    entries.sort((a: any, b: any) => String(a.name).localeCompare(String(b.name)));
    for (const entry of entries) {
      if (output.length >= maximumEntries) break;
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(directory, entry.name);
      const rel = path.relative(root, absolute);
      if (entry.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name)) continue;
        output.push({ path: rel, type: "directory" });
        if (depth < maximumDepth) await visit(absolute, depth + 1);
      } else if (entry.isFile()) output.push({ path: rel, type: "file" });
    }
  }
  await visit(start, 1);
  return output;
}

async function runProcess(argv: string[], cwd: string, timeoutMs: number, maximumBytes: number, signal?: AbortSignal): Promise<ProcessResult> {
  if (argv.length === 0 || argv.length > 64 || argv.some((item) => typeof item !== "string" || item.length === 0 || item.length > 4096 || item.includes("\0"))) {
    throw new OpsHavenError("INVALID_ARGUMENTS", "Command argv is invalid.");
  }
  const started = Date.now();
  const child = spawn(argv[0] as string, argv.slice(1), {
    cwd,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, LANG: "C", LC_ALL: "C" },
  });
  return await new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let collected = 0;
    let truncated = false;
    let timedOut = false;
    let cancelled = signal?.aborted === true;
    const collect = (which: "stdout" | "stderr", chunk: Uint8Array): void => {
      const text = Buffer.from(chunk).toString("utf8");
      const available = Math.max(0, maximumBytes - collected);
      if (available <= 0) { truncated = true; return; }
      if (chunk.length > available) truncated = true;
      const accepted = chunk.length <= available ? text : text.slice(0, available);
      collected += Math.min(chunk.length, available);
      if (which === "stdout") stdout += accepted;
      else stderr += accepted;
    };
    child.stdout.on("data", (chunk: Uint8Array) => collect("stdout", chunk));
    child.stderr.on("data", (chunk: Uint8Array) => collect("stderr", chunk));
    const onAbort = (): void => { cancelled = true; child.kill("SIGTERM"); };
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs);
    child.on("error", (error: unknown) => {
      clearTimeout(timer);
      if (signal) signal.removeEventListener("abort", onAbort);
      reject(error);
    });
    child.on("close", (code: number | null, closeSignal: string | null) => {
      clearTimeout(timer);
      if (signal) signal.removeEventListener("abort", onAbort);
      resolve({ argv, cwd, exitCode: code, signal: closeSignal, stdout, stderr, durationMs: Date.now() - started, timedOut, cancelled, truncated });
    });
  });
}

async function git(workspace: WorkspaceRecord, argv: string[], maximumBytes = DEFAULT_MAX_BYTES, signal?: AbortSignal): Promise<ProcessResult> {
  if (!workspace.project.git) throw new OpsHavenError("INVALID_ARGUMENTS", "Workspace is not a detected Git worktree.");
  return await runProcess(["git", "-C", workspace.root, ...argv], workspace.root, 30_000, maximumBytes, signal);
}

async function detectPytest(workspace: WorkspaceRecord): Promise<boolean> {
  if (workspace.project.manifests.includes("pytest.ini")) return true;
  for (const candidate of ["pyproject.toml", "requirements.txt"] as const) {
    if (!workspace.project.manifests.includes(candidate)) continue;
    try {
      const file = await readText(workspace, candidate, 512 * 1024);
      if (/\bpytest\b/i.test(file.text)) return true;
    } catch {}
  }
  return false;
}

export async function discoverWorkspaceTasks(workspace: WorkspaceRecord): Promise<DiscoveredTask[]> {
  const tasks: DiscoveredTask[] = [];
  if (workspace.project.manifests.includes("package.json")) {
    try {
      const packageFile = await readText(workspace, "package.json", 1024 * 1024);
      const parsed = JSON.parse(packageFile.text) as Record<string, unknown>;
      const scripts = parsed.scripts && typeof parsed.scripts === "object" && !Array.isArray(parsed.scripts) ? parsed.scripts as Record<string, unknown> : {};
      const declaredManager = typeof parsed.packageManager === "string" ? parsed.packageManager.split("@")[0] : undefined;
      const manager = declaredManager === "pnpm" || declaredManager === "yarn" || declaredManager === "npm"
        ? declaredManager
        : workspace.project.manifests.includes("pnpm-lock.yaml") ? "pnpm" : workspace.project.manifests.includes("yarn.lock") ? "yarn" : "npm";
      for (const script of Object.keys(scripts).sort()) {
        if (typeof scripts[script] !== "string") continue;
        tasks.push({ id: `${manager}:${script}`, label: `${manager} run ${script}`, argv: [manager, "run", script], source: "package.json#scripts" });
      }
    } catch {}
  }
  if (workspace.project.manifests.includes("Cargo.toml")) {
    tasks.push({ id: "cargo:check", label: "cargo check", argv: ["cargo", "check"], source: "Cargo.toml" });
    tasks.push({ id: "cargo:test", label: "cargo test", argv: ["cargo", "test"], source: "Cargo.toml" });
  }
  if (await detectPytest(workspace)) tasks.push({ id: "python:pytest", label: "pytest", argv: ["pytest"], source: "pytest project metadata" });
  if (workspace.project.manifests.includes("go.mod")) tasks.push({ id: "go:test", label: "go test ./...", argv: ["go", "test", "./..."], source: "go.mod" });
  return tasks;
}

function resultEnvelope(operation: string, startedAt: string, data: Record<string, unknown>, mutation = false, truncated = false): ResultEnvelope {
  return { ok: true, requestId: requestId(), operation, data, meta: { startedAt, finishedAt: new Date().toISOString(), dryRun: false, mutation, truncated, redactions: 0, auditRecorded: false } };
}
function errorEnvelope(operation: string, startedAt: string, error: unknown): ResultEnvelope {
  const safe = asOpsHavenError(error);
  return { ok: false, requestId: requestId(), operation, error: { code: safe.code, message: safe.message, retryable: safe.retryable, ...(safe.safeDetails ? { details: { ...safe.safeDetails } } : {}) }, meta: { startedAt, finishedAt: new Date().toISOString(), dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: false } };
}

export class WorkspaceToolExecutor {
  constructor(readonly store = new WorkspaceStore()) {}

  static handles(name: string): boolean { return LOCAL_TOOL_NAMES.has(name); }

  async execute(operation: string, rawArgs: unknown, _approvalToken?: string, _actor?: string, signal?: AbortSignal): Promise<ResultEnvelope> {
    const startedAt = new Date().toISOString();
    try {
      if (!LOCAL_TOOL_NAMES.has(operation)) throw new OpsHavenError("UNKNOWN_OPERATION", "Unknown local workspace operation.");
      const args = argsObject(rawArgs);
      const workspace = await this.store.get(workspaceArg(args));
      if (signal?.aborted) throw new OpsHavenError("CANCELLED", "Operation was cancelled.", true);

      if (["workspace_info", "workspace_tree", "list_files", "read_file", "read_files", "search_files", "file_hash", "code_context", "git_status", "git_diff", "git_log", "project_info", "discover_tasks"].includes(operation)) requirePermission(workspace, "read");
      if (["create_file", "replace_file", "edit_file", "edit_files"].includes(operation)) requirePermission(workspace, "edit");
      if (operation === "run_task") requirePermission(workspace, "tasks");
      if (operation === "run_command") requirePermission(workspace, "commands");

      switch (operation) {
        case "workspace_info": {
          const root = await existingPath(workspace, ".", "directory");
          return resultEnvelope(operation, startedAt, { id: workspace.id, name: workspace.name, root: workspace.root, available: root.stat.isDirectory(), permissions: workspace.permissions, project: workspace.project });
        }
        case "workspace_tree": {
          const start = await existingPath(workspace, relative(args.path), "directory");
          const depth = integerValue(args.depth, 4, 1, 8, "depth");
          const maximum = integerValue(args.maxEntries, 400, 1, 2000, "maxEntries");
          const entries = await walk(workspace.root, start.absolute, maximum, depth);
          return resultEnvelope(operation, startedAt, { path: start.relative, entries, truncated: entries.length >= maximum }, false, entries.length >= maximum);
        }
        case "list_files": {
          const directory = await existingPath(workspace, relative(args.path), "directory");
          const maximum = integerValue(args.maxEntries, 250, 1, 1000, "maxEntries");
          const raw = await fs.readdir(directory.absolute, { withFileTypes: true });
          raw.sort((a: any, b: any) => String(a.name).localeCompare(String(b.name)));
          const entries = raw.filter((entry: any) => !entry.isSymbolicLink()).slice(0, maximum).map((entry: any) => ({ name: entry.name, path: path.relative(workspace.root, path.join(directory.absolute, entry.name)), type: entry.isDirectory() ? "directory" : entry.isFile() ? "file" : "other", skippedByTree: entry.isDirectory() && SKIP_DIRECTORIES.has(entry.name) }));
          return resultEnvelope(operation, startedAt, { path: directory.relative, entries, truncated: raw.length > maximum }, false, raw.length > maximum);
        }
        case "read_file": {
          const maximum = integerValue(args.maxBytes, DEFAULT_MAX_BYTES, 1024, MAX_TOOL_BYTES, "maxBytes");
          const file = await readText(workspace, args.path, maximum);
          return resultEnvelope(operation, startedAt, { path: file.path, content: file.text, hash: file.hash, bytes: file.bytes });
        }
        case "read_files": {
          if (!Array.isArray(args.paths) || args.paths.length < 1 || args.paths.length > 20) throw new OpsHavenError("INVALID_ARGUMENTS", "paths must contain 1-20 project files.");
          const maximum = integerValue(args.maxBytesEach, 128 * 1024, 1024, 512 * 1024, "maxBytesEach");
          const files = [];
          for (const item of args.paths) {
            const file = await readText(workspace, item, maximum);
            files.push({ path: file.path, content: file.text, hash: file.hash, bytes: file.bytes });
          }
          return resultEnvelope(operation, startedAt, { files });
        }
        case "search_files": {
          const query = stringValue(args.query, "query", 256);
          const start = await existingPath(workspace, relative(args.path), "directory");
          const maximum = integerValue(args.maxResults, 50, 1, 200, "maxResults");
          const all = await walk(workspace.root, start.absolute, MAX_SEARCH_FILES, 64);
          const matches: Array<{ path: string; line: number; text: string }> = [];
          const needle = query.toLowerCase();
          let scanned = 0;
          for (const entry of all) {
            if (entry.type !== "file" || matches.length >= maximum) continue;
            scanned += 1;
            try {
              const file = await readText(workspace, entry.path, 512 * 1024);
              const lines = file.text.split("\n");
              for (let index = 0; index < lines.length && matches.length < maximum; index += 1) {
                const line = lines[index] as string;
                if (line.toLowerCase().includes(needle)) matches.push({ path: entry.path, line: index + 1, text: line.slice(0, 400) });
              }
            } catch {}
          }
          const truncated = matches.length >= maximum || all.length >= MAX_SEARCH_FILES;
          return resultEnvelope(operation, startedAt, { query, matches, scannedFiles: scanned, truncated }, false, truncated);
        }
        case "file_hash": {
          const file = await readText(workspace, args.path, MAX_EDIT_BYTES);
          return resultEnvelope(operation, startedAt, { path: file.path, hash: file.hash, bytes: file.bytes });
        }
        case "code_context": {
          const file = await readText(workspace, args.path, MAX_TOOL_BYTES);
          const source = file.text.split("\n");
          const requestedStart = integerValue(args.startLine, 1, 1, 1_000_000, "startLine");
          const requestedEnd = args.endLine === undefined ? requestedStart : integerValue(args.endLine, requestedStart, 1, 1_000_000, "endLine");
          if (requestedEnd < requestedStart) throw new OpsHavenError("INVALID_ARGUMENTS", "endLine must not be before startLine.");
          const context = integerValue(args.contextLines, 5, 0, 50, "contextLines");
          const start = Math.max(1, requestedStart - context);
          const end = Math.min(source.length, requestedEnd + context);
          const lines = source.slice(start - 1, end).map((text, index) => ({ line: start + index, text }));
          return resultEnvelope(operation, startedAt, { path: file.path, hash: file.hash, totalLines: source.length, startLine: start, endLine: end, lines });
        }
        case "git_status": {
          const output = await git(workspace, ["status", "--porcelain=v1", "-z", "--untracked-files=all"], DEFAULT_MAX_BYTES, signal);
          const fields = output.stdout.split("\0").filter(Boolean);
          const entries = fields.map((item) => ({ index: item.slice(0, 1), worktree: item.slice(1, 2), path: item.slice(3) }));
          return resultEnvelope(operation, startedAt, { entries, clean: entries.length === 0, exitCode: output.exitCode }, false, output.truncated);
        }
        case "git_diff": {
          const staged = booleanValue(args.staged, false, "staged");
          const maximum = integerValue(args.maxBytes, DEFAULT_MAX_BYTES, 1024, MAX_TOOL_BYTES, "maxBytes");
          const argv = ["diff", "--no-ext-diff", "--no-color", ...(staged ? ["--cached"] : [])];
          if (args.path !== undefined) argv.push("--", relative(args.path));
          const output = await git(workspace, argv, maximum, signal);
          return resultEnvelope(operation, startedAt, { staged, diff: output.stdout, exitCode: output.exitCode, truncated: output.truncated }, false, output.truncated);
        }
        case "git_log": {
          const count = integerValue(args.maxCount, 10, 1, 50, "maxCount");
          const output = await git(workspace, ["log", `-${count}`, "--date=iso-strict", "--pretty=format:%H%x09%an%x09%aI%x09%s"], DEFAULT_MAX_BYTES, signal);
          const commits = output.stdout.split("\n").filter(Boolean).map((line) => {
            const [hash, author, authoredAt, ...subject] = line.split("\t");
            return { hash, author, authoredAt, subject: subject.join("\t") };
          });
          return resultEnvelope(operation, startedAt, { commits, exitCode: output.exitCode }, false, output.truncated);
        }
        case "project_info": {
          const project = await detectWorkspaceProject(workspace.root);
          const tasks = await discoverWorkspaceTasks({ ...workspace, project });
          return resultEnvelope(operation, startedAt, { project, taskCount: tasks.length });
        }
        case "discover_tasks": {
          const tasks = await discoverWorkspaceTasks(workspace);
          return resultEnvelope(operation, startedAt, { tasks });
        }
        case "create_file": {
          const target = await writeTarget(workspace, args.path);
          const content = typeof args.content === "string" ? args.content : null;
          if (content === null || Buffer.byteLength(content, "utf8") > MAX_EDIT_BYTES) throw new OpsHavenError("INVALID_ARGUMENTS", "content is invalid or too large.");
          try {
            const stat = await fs.lstat(target.absolute);
            if (stat) throw new OpsHavenError("INVALID_ARGUMENTS", "Project file already exists.");
          } catch (error) {
            if ((error as any)?.code !== "ENOENT") throw error;
          }
          await atomicReplace(target.absolute, content, 0o644);
          return resultEnvelope(operation, startedAt, { path: target.relative, hash: digest(content), bytes: Buffer.byteLength(content, "utf8") }, true);
        }
        case "replace_file": {
          const file = await readText(workspace, args.path, MAX_EDIT_BYTES);
          const expected = stringValue(args.expectedHash, "expectedHash", 64);
          if (file.hash !== expected) throw new OpsHavenError("INVALID_ARGUMENTS", "File changed after it was read.", false, { conflict: true, path: file.path, expectedHash: expected, currentHash: file.hash });
          if (typeof args.content !== "string" || Buffer.byteLength(args.content, "utf8") > MAX_EDIT_BYTES) throw new OpsHavenError("INVALID_ARGUMENTS", "content is invalid or too large.");
          const target = await existingPath(workspace, file.path, "file");
          await atomicReplace(target.absolute, args.content, file.mode);
          return resultEnvelope(operation, startedAt, { path: file.path, previousHash: file.hash, hash: digest(args.content), bytes: Buffer.byteLength(args.content, "utf8") }, true);
        }
        case "edit_file": {
          const file = await readText(workspace, args.path, MAX_EDIT_BYTES);
          const expected = stringValue(args.expectedHash, "expectedHash", 64);
          if (file.hash !== expected) throw new OpsHavenError("INVALID_ARGUMENTS", "File changed after it was read.", false, { conflict: true, path: file.path, expectedHash: expected, currentHash: file.hash });
          const oldText = stringValue(args.oldText, "oldText", MAX_EDIT_BYTES);
          if (typeof args.newText !== "string") throw new OpsHavenError("INVALID_ARGUMENTS", "newText is invalid.");
          const first = file.text.indexOf(oldText);
          if (first < 0 || file.text.indexOf(oldText, first + oldText.length) >= 0) throw new OpsHavenError("INVALID_ARGUMENTS", "Target text must match exactly once.");
          const updated = `${file.text.slice(0, first)}${args.newText}${file.text.slice(first + oldText.length)}`;
          const target = await existingPath(workspace, file.path, "file");
          await atomicReplace(target.absolute, updated, file.mode);
          return resultEnvelope(operation, startedAt, { path: file.path, previousHash: file.hash, hash: digest(updated), bytes: Buffer.byteLength(updated, "utf8") }, true);
        }
        case "edit_files": {
          if (!Array.isArray(args.edits) || args.edits.length < 1 || args.edits.length > 20) throw new OpsHavenError("INVALID_ARGUMENTS", "edits must contain 1-20 entries.");
          const prepared: Array<{ file: Awaited<ReturnType<typeof readText>>; absolute: string; updated: string }> = [];
          const seen = new Set<string>();
          for (const raw of args.edits) {
            const edit = argsObject(raw);
            const file = await readText(workspace, edit.path, MAX_EDIT_BYTES);
            if (seen.has(file.path)) throw new OpsHavenError("INVALID_ARGUMENTS", "Each file may appear only once in edit_files.");
            seen.add(file.path);
            const expected = stringValue(edit.expectedHash, "expectedHash", 64);
            if (file.hash !== expected) throw new OpsHavenError("INVALID_ARGUMENTS", "File changed after it was read.", false, { conflict: true, path: file.path, expectedHash: expected, currentHash: file.hash });
            const oldText = stringValue(edit.oldText, "oldText", MAX_EDIT_BYTES);
            if (typeof edit.newText !== "string") throw new OpsHavenError("INVALID_ARGUMENTS", "newText is invalid.");
            const first = file.text.indexOf(oldText);
            if (first < 0 || file.text.indexOf(oldText, first + oldText.length) >= 0) throw new OpsHavenError("INVALID_ARGUMENTS", `Target text in ${file.path} must match exactly once.`);
            const updated = `${file.text.slice(0, first)}${edit.newText}${file.text.slice(first + oldText.length)}`;
            if (Buffer.byteLength(updated, "utf8") > MAX_EDIT_BYTES) throw new OpsHavenError("OUTPUT_LIMIT", `Edited file ${file.path} exceeds the edit bound.`);
            const target = await existingPath(workspace, file.path, "file");
            prepared.push({ file, absolute: target.absolute, updated });
          }
          for (const item of prepared) await atomicReplace(item.absolute, item.updated, item.file.mode);
          return resultEnvelope(operation, startedAt, { files: prepared.map((item) => ({ path: item.file.path, previousHash: item.file.hash, hash: digest(item.updated) })), preflighted: true }, true);
        }
        case "run_task": {
          const taskId = stringValue(args.taskId, "taskId", 256);
          const tasks = await discoverWorkspaceTasks(workspace);
          const task = tasks.find((item) => item.id === taskId);
          if (!task) throw new OpsHavenError("INVALID_ARGUMENTS", "Task is not present in current project metadata.");
          const extra = args.args === undefined ? [] : args.args;
          if (!Array.isArray(extra) || extra.length > 32 || extra.some((item) => typeof item !== "string" || item.length > 512 || item.includes("\0"))) throw new OpsHavenError("INVALID_ARGUMENTS", "Task args are invalid.");
          const cwdPath = args.cwd === undefined ? { absolute: workspace.root, relative: "." } : await existingPath(workspace, relative(args.cwd), "directory");
          const timeoutMs = integerValue(args.timeoutMs, DEFAULT_TIMEOUT_MS, 100, MAX_TIMEOUT_MS, "timeoutMs");
          const maximum = integerValue(args.maxBytes, DEFAULT_MAX_BYTES, 1024, MAX_TOOL_BYTES, "maxBytes");
          const output = await runProcess([...task.argv, ...(extra as string[])], cwdPath.absolute, timeoutMs, maximum, signal);
          return resultEnvelope(operation, startedAt, { task, ...output }, false, output.truncated);
        }
        case "run_command": {
          if (!Array.isArray(args.argv) || args.argv.length < 1 || args.argv.length > 64) throw new OpsHavenError("INVALID_ARGUMENTS", "argv must contain 1-64 strings.");
          const argv = args.argv.map((item, index) => stringValue(item, `argv[${index}]`, 4096));
          const executable = path.basename(argv[0] as string).toLowerCase();
          if (["sudo", "su", "doas", "pkexec"].includes(executable)) throw new OpsHavenError("POLICY_DENIED", "Privilege-escalation commands are not available in V1.2.");
          const cwdPath = args.cwd === undefined ? { absolute: workspace.root, relative: "." } : await existingPath(workspace, relative(args.cwd), "directory");
          const timeoutMs = integerValue(args.timeoutMs, DEFAULT_TIMEOUT_MS, 100, MAX_TIMEOUT_MS, "timeoutMs");
          const maximum = integerValue(args.maxBytes, DEFAULT_MAX_BYTES, 1024, MAX_TOOL_BYTES, "maxBytes");
          const output = await runProcess(argv, cwdPath.absolute, timeoutMs, maximum, signal);
          return resultEnvelope(operation, startedAt, output as unknown as Record<string, unknown>, false, output.truncated);
        }
        default:
          throw new OpsHavenError("UNKNOWN_OPERATION", "Unknown local workspace operation.");
      }
    } catch (error) {
      return errorEnvelope(operation, startedAt, error);
    }
  }
}
