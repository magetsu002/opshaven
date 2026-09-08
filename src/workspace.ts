import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { OpsHavenError } from "./errors.js";
import { operatorStateRoot } from "./operator-state.js";

export interface WorkspacePermissions {
  read: boolean;
  edit: boolean;
  tasks: boolean;
  commands: boolean;
}

export interface WorkspaceProjectMetadata {
  ecosystems: string[];
  manifests: string[];
  git: boolean;
  packageName?: string;
}

export interface WorkspaceRecord {
  id: string;
  name: string;
  root: string;
  addedAt: string;
  permissions: WorkspacePermissions;
  project: WorkspaceProjectMetadata;
}

interface WorkspaceDocument {
  version: 1;
  workspaces: WorkspaceRecord[];
}

export interface RegisterWorkspaceOptions {
  name?: string;
  permissions?: Partial<WorkspacePermissions>;
}

const WORKSPACE_ID = /^[a-z][a-z0-9._-]{0,63}$/;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const PROJECT_MANIFESTS = [
  "package.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "package-lock.json",
  "Cargo.toml",
  "pyproject.toml",
  "requirements.txt",
  "pytest.ini",
  "tox.ini",
  "go.mod",
] as const;

function expandRoot(value: string): string {
  const home = homedir();
  if (value === "~") return home;
  if (value.startsWith("~/")) return path.join(home, value.slice(2));
  return path.resolve(value);
}

function defaultPermissions(value?: Partial<WorkspacePermissions>): WorkspacePermissions {
  return {
    read: value?.read ?? true,
    edit: value?.edit ?? false,
    tasks: value?.tasks ?? false,
    commands: value?.commands ?? false,
  };
}

function validPermissions(value: unknown): value is WorkspacePermissions {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return typeof item.read === "boolean"
    && typeof item.edit === "boolean"
    && typeof item.tasks === "boolean"
    && typeof item.commands === "boolean"
    && Object.keys(item).every((key) => ["read", "edit", "tasks", "commands"].includes(key));
}

function validProject(value: unknown): value is WorkspaceProjectMetadata {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return Array.isArray(item.ecosystems)
    && item.ecosystems.every((entry) => typeof entry === "string")
    && Array.isArray(item.manifests)
    && item.manifests.every((entry) => typeof entry === "string")
    && typeof item.git === "boolean"
    && (item.packageName === undefined || typeof item.packageName === "string");
}

function validRecord(value: unknown): value is WorkspaceRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return typeof item.id === "string"
    && WORKSPACE_ID.test(item.id)
    && typeof item.name === "string"
    && item.name.length > 0
    && item.name.length <= 128
    && typeof item.root === "string"
    && path.isAbsolute(item.root)
    && path.normalize(item.root) === item.root
    && typeof item.addedAt === "string"
    && validPermissions(item.permissions)
    && validProject(item.project);
}

async function privateDirectory(directory: string): Promise<void> {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new OpsHavenError("CONFIG_INVALID", "Workspace state directory is unsafe.");
  await fs.chmod(directory, 0o700);
}

async function atomicWrite(file: string, content: string): Promise<void> {
  const temporary = `${file}.opshaven-${process.pid}-${Date.now()}`;
  try {
    await fs.writeFile(temporary, content, { mode: 0o600, flag: "wx" });
    await fs.chmod(temporary, 0o600);
    await fs.rename(temporary, file);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

async function regularFile(root: string, relative: string): Promise<boolean> {
  try {
    const candidate = path.join(root, relative);
    const stat = await fs.lstat(candidate);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

async function gitMetadataPresent(root: string): Promise<boolean> {
  try {
    const stat = await fs.lstat(path.join(root, ".git"));
    return !stat.isSymbolicLink() && (stat.isDirectory() || stat.isFile());
  } catch {
    return false;
  }
}

async function packageName(root: string): Promise<string | undefined> {
  const file = path.join(root, "package.json");
  try {
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_MANIFEST_BYTES) return undefined;
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as Record<string, unknown>;
    return typeof parsed.name === "string" && parsed.name.length > 0 && parsed.name.length <= 214 ? parsed.name : undefined;
  } catch {
    return undefined;
  }
}

export async function detectWorkspaceProject(root: string): Promise<WorkspaceProjectMetadata> {
  const manifests: string[] = [];
  for (const manifest of PROJECT_MANIFESTS) if (await regularFile(root, manifest)) manifests.push(manifest);
  const ecosystems: string[] = [];
  if (manifests.some((item) => ["package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"].includes(item))) ecosystems.push("javascript");
  if (manifests.includes("Cargo.toml")) ecosystems.push("rust");
  if (manifests.some((item) => ["pyproject.toml", "requirements.txt", "pytest.ini", "tox.ini"].includes(item))) ecosystems.push("python");
  if (manifests.includes("go.mod")) ecosystems.push("go");
  const name = await packageName(root);
  return {
    ecosystems,
    manifests,
    git: await gitMetadataPresent(root),
    ...(name ? { packageName: name } : {}),
  };
}

export async function canonicalWorkspaceRoot(value: string): Promise<string> {
  if (typeof value !== "string" || value.trim().length === 0 || value.includes("\0")) throw new OpsHavenError("CONFIG_INVALID", "Workspace root is invalid.");
  const requested = path.normalize(expandRoot(value.trim()));
  let stat: any;
  try { stat = await fs.lstat(requested); }
  catch { throw new OpsHavenError("CONFIG_INVALID", "Workspace root does not exist."); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new OpsHavenError("CONFIG_INVALID", "Workspace root must be a real local directory, not a symlink.");
  const real = await fs.realpath(requested);
  if (real !== requested) throw new OpsHavenError("CONFIG_INVALID", "Workspace root resolves through a symlink and was rejected.");
  const verified = await fs.lstat(real);
  if (!verified.isDirectory() || verified.isSymbolicLink()) throw new OpsHavenError("CONFIG_INVALID", "Workspace root is unsafe.");
  return real;
}

function slug(value: string): string {
  let result = value.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^[^a-z]+/, "").replace(/-+/g, "-").replace(/[-._]+$/g, "");
  if (!result) result = "workspace";
  if (!/^[a-z]/.test(result)) result = `w-${result}`;
  return result.slice(0, 48);
}

function rootDigest(root: string): string {
  return createHash("sha256").update(root).digest("hex").slice(0, 10);
}

export class WorkspaceStore {
  readonly stateRoot: string;
  readonly file: string;

  constructor(stateRoot = operatorStateRoot()) {
    this.stateRoot = stateRoot;
    this.file = path.join(stateRoot, "workspaces.json");
  }

  async load(): Promise<WorkspaceDocument> {
    try {
      const stat = await fs.lstat(this.file);
      if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) throw new OpsHavenError("CONFIG_INVALID", "Workspace registry is unsafe.");
      const parsed = JSON.parse(await fs.readFile(this.file, "utf8")) as Record<string, unknown>;
      if (parsed.version !== 1 || !Array.isArray(parsed.workspaces) || !parsed.workspaces.every(validRecord)) throw new OpsHavenError("CONFIG_INVALID", "Workspace registry is invalid.");
      const records = parsed.workspaces as WorkspaceRecord[];
      if (new Set(records.map((item) => item.id)).size !== records.length || new Set(records.map((item) => item.root)).size !== records.length) {
        throw new OpsHavenError("CONFIG_INVALID", "Workspace registry contains duplicate identities.");
      }
      return { version: 1, workspaces: records };
    } catch (error) {
      if ((error as any)?.code === "ENOENT") return { version: 1, workspaces: [] };
      throw error;
    }
  }

  private async save(document: WorkspaceDocument): Promise<void> {
    await privateDirectory(this.stateRoot);
    await atomicWrite(this.file, `${JSON.stringify(document, null, 2)}\n`);
  }

  async list(): Promise<WorkspaceRecord[]> {
    return [...(await this.load()).workspaces].sort((a, b) => a.id.localeCompare(b.id));
  }

  async get(id: string): Promise<WorkspaceRecord> {
    if (!WORKSPACE_ID.test(id)) throw new OpsHavenError("CONFIG_INVALID", "Workspace id is invalid.");
    const record = (await this.load()).workspaces.find((item) => item.id === id);
    if (!record) throw new OpsHavenError("CONFIG_INVALID", `Workspace "${id}" is not registered.`);
    return record;
  }

  async register(rootInput: string, options: RegisterWorkspaceOptions = {}): Promise<WorkspaceRecord> {
    const root = await canonicalWorkspaceRoot(rootInput);
    const document = await this.load();
    const duplicate = document.workspaces.find((item) => item.root === root);
    if (duplicate) throw new OpsHavenError("CONFIG_INVALID", `Workspace root is already registered as "${duplicate.id}".`);
    const name = options.name?.trim() || path.basename(root);
    if (!name || name.length > 128 || /[\r\n\0]/.test(name)) throw new OpsHavenError("CONFIG_INVALID", "Workspace name is invalid.");
    const base = slug(name);
    const id = document.workspaces.some((item) => item.id === base) ? `${base.slice(0, 52)}-${rootDigest(root)}` : base;
    if (!WORKSPACE_ID.test(id) || document.workspaces.some((item) => item.id === id)) throw new OpsHavenError("CONFIG_INVALID", "A stable workspace id could not be allocated.");
    const record: WorkspaceRecord = {
      id,
      name,
      root,
      addedAt: new Date().toISOString(),
      permissions: defaultPermissions(options.permissions),
      project: await detectWorkspaceProject(root),
    };
    await this.save({ version: 1, workspaces: [...document.workspaces, record] });
    return record;
  }

  async updatePermissions(id: string, patch: Partial<WorkspacePermissions>): Promise<WorkspaceRecord> {
    const document = await this.load();
    const index = document.workspaces.findIndex((item) => item.id === id);
    if (index < 0) throw new OpsHavenError("CONFIG_INVALID", `Workspace "${id}" is not registered.`);
    for (const [key, value] of Object.entries(patch)) {
      if (!["read", "edit", "tasks", "commands"].includes(key) || typeof value !== "boolean") throw new OpsHavenError("CONFIG_INVALID", "Workspace permission update is invalid.");
    }
    const current = document.workspaces[index] as WorkspaceRecord;
    const updated: WorkspaceRecord = { ...current, permissions: { ...current.permissions, ...patch } };
    const workspaces = [...document.workspaces];
    workspaces[index] = updated;
    await this.save({ version: 1, workspaces });
    return updated;
  }

  async refresh(id: string): Promise<WorkspaceRecord> {
    const document = await this.load();
    const index = document.workspaces.findIndex((item) => item.id === id);
    if (index < 0) throw new OpsHavenError("CONFIG_INVALID", `Workspace "${id}" is not registered.`);
    const current = document.workspaces[index] as WorkspaceRecord;
    const root = await canonicalWorkspaceRoot(current.root);
    const updated: WorkspaceRecord = { ...current, root, project: await detectWorkspaceProject(root) };
    const workspaces = [...document.workspaces];
    workspaces[index] = updated;
    await this.save({ version: 1, workspaces });
    return updated;
  }
}
