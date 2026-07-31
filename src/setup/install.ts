import { createHash, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { readRegularFile, readRegularTextFile } from "../safe-fs.js";
import type { RemoteSetupPreflightReport } from "./preflight.js";
import type { RemoteSetupConfig } from "./remote.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export interface RuntimeManifestEntry {
  readonly path: string;
  readonly sha256: string;
  readonly executable: boolean;
}

export interface RuntimeManifest {
  readonly version: 1;
  readonly files: readonly RuntimeManifestEntry[];
  readonly treeSha256: string;
}

export interface RemoteInstallResult {
  readonly ok: true;
  readonly changed: readonly string[];
  readonly runtimeTreeSha256: string;
  readonly backupRoot: string;
  readonly receiptId: string;
}

const REQUIRED_RUNTIME_FILES = [
  "src/capabilities.js",
  "src/capability-declaration.js",
  "src/config.js",
  "src/errors.js",
  "src/safe-fs.js",
  "src/remote/authenticated-protocol.js",
  "src/remote/confinement.js",
  "src/remote/read-only-dispatcher.js",
  "src/remote/read-only-handlers.js",
  "src/remote/read-only-policy.js",
  "src/remote/read-only-protocol.js",
  "src/remote/runner.js",
] as const;

function relativePath(root: string, filePath: string): string {
  const relative = path.relative(root, filePath).split(path.sep).join("/");
  if (!relative || relative.startsWith("../") || relative.includes("/../") || path.isAbsolute(relative)) throw new OpsHavenError("CONFIG_INVALID", "Runtime file escaped its reviewed root.");
  return relative;
}

async function collectFiles(root: string, current = root, result: string[] = []): Promise<string[]> {
  const entries = await fs.readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(current, entry.name);
    if (entry.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Runtime tree cannot contain symbolic links.");
    if (entry.isDirectory()) await collectFiles(root, full, result);
    else if (entry.isFile()) result.push(full);
    else throw new OpsHavenError("POLICY_DENIED", "Runtime tree contains an unsupported filesystem object.");
    if (result.length > 4096) throw new OpsHavenError("OUTPUT_LIMIT", "Runtime tree contains too many files.");
  }
  return result;
}

function canonicalManifestFiles(files: readonly RuntimeManifestEntry[]): string {
  return JSON.stringify(files.map((item) => ({ executable: item.executable, path: item.path, sha256: item.sha256 })));
}

async function readRuntimeFile(filePath: string): Promise<Uint8Array> {
  return await readRegularFile(filePath, "Read-only runtime file", { maxBytes: 33554432, code: "POLICY_DENIED" });
}

export async function buildRuntimeManifest(runtimeRoot: string): Promise<RuntimeManifest> {
  const rootStat = await fs.lstat(runtimeRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new OpsHavenError("POLICY_DENIED", "Read-only runtime root must be a real directory.");
  const fullPaths = (await collectFiles(runtimeRoot)).sort();
  const entries: RuntimeManifestEntry[] = [];
  let totalBytes = 0;
  for (const fullPath of fullPaths) {
    const bytes = await readRuntimeFile(fullPath);
    totalBytes += bytes.length;
    if (totalBytes > 33554432) throw new OpsHavenError("OUTPUT_LIMIT", "Read-only runtime exceeds the reviewed size limit.");
    const relative = relativePath(runtimeRoot, fullPath);
    entries.push(Object.freeze({ path: relative, sha256: createHash("sha256").update(bytes).digest("hex"), executable: relative === "src/remote/read-only-dispatcher.js" }));
  }
  const available = new Set(entries.map((item) => item.path));
  for (const required of REQUIRED_RUNTIME_FILES) if (!available.has(required)) throw new OpsHavenError("POLICY_DENIED", `Read-only runtime is incomplete: ${required} is missing.`);
  const files = Object.freeze(entries);
  return Object.freeze({ version: 1, files, treeSha256: createHash("sha256").update(canonicalManifestFiles(files)).digest("hex") });
}

export function renderReadonlyWrapper(template: string, nodePath: string, runtimeRoot: string): string {
  for (const required of ["--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--reset-env"]) {
    if (!template.includes(required)) throw new OpsHavenError("POLICY_DENIED", `Read-only wrapper template is missing ${required}.`);
  }
  if (template.includes("--bounding-set")) throw new OpsHavenError("POLICY_DENIED", "Read-only wrapper template contains the incompatible bounding-set transition.");
  if (!/^\/[A-Za-z0-9._/+-]+$/.test(nodePath) || !/^\/[A-Za-z0-9._/+-]+$/.test(runtimeRoot)) throw new OpsHavenError("CONFIG_INVALID", "Resolved wrapper paths are invalid.");
  const dispatcher = `${runtimeRoot}/src/remote/read-only-dispatcher.js`;
  let rendered = template.replace("/usr/bin/node", nodePath);
  rendered = rendered.replace("/usr/lib/opshaven/read-only-dispatcher.js", dispatcher);
  if (!rendered.includes(`${nodePath} ${dispatcher}`)) throw new OpsHavenError("POLICY_DENIED", "Read-only wrapper template did not contain the fixed executable placeholders.");
  return rendered.endsWith("\n") ? rendered : `${rendered}\n`;
}

export function buildRestrictedAuthorizedKey(publicKey: string, wrapperPath: string, configPath: string): string {
  const line = publicKey.trim();
  if (line.includes("\n") || !/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]{1,128})?$/.test(line)) throw new OpsHavenError("CONFIG_INVALID", "Restricted SSH public key must be one valid Ed25519 key line.");
  const command = `${wrapperPath} --config ${configPath}`;
  if (!/^\/[A-Za-z0-9._/-]+ --config \/[A-Za-z0-9._/-]+$/.test(command)) throw new OpsHavenError("CONFIG_INVALID", "Forced command contains an unsafe path.");
  return `restrict,command="${command}" ${line}\n`;
}

async function copyRuntime(runtimeRoot: string, stageRuntime: string, manifest: RuntimeManifest): Promise<void> {
  for (const item of manifest.files) {
    const source = path.join(runtimeRoot, ...item.path.split("/"));
    const destination = path.join(stageRuntime, ...item.path.split("/"));
    await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    const bytes = await readRuntimeFile(source);
    if (createHash("sha256").update(bytes).digest("hex") !== item.sha256) throw new OpsHavenError("POLICY_DENIED", "Runtime changed while it was being staged.");
    await fs.writeFile(destination, bytes, { mode: item.executable ? 0o700 : 0o600 });
  }
}

function parseInstallResult(stdout: string, receiptId: string): RemoteInstallResult {
  let value: unknown;
  try { value = JSON.parse(stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote installer did not return valid JSON."); }
  if (!value || typeof value !== "object") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote installer response is malformed.");
  const result = value as Record<string, unknown>;
  if (result.ok !== true || !Array.isArray(result.changed) || typeof result.runtimeTreeSha256 !== "string" || !/^[a-f0-9]{64}$/.test(result.runtimeTreeSha256) || typeof result.backupRoot !== "string") {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote installer response failed validation.");
  }
  const changed = result.changed.map((item) => {
    if (typeof item !== "string" || !item.startsWith("/")) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote installer changed-path evidence is invalid.");
    return item;
  });
  return Object.freeze({ ok: true, changed: Object.freeze(changed), runtimeTreeSha256: result.runtimeTreeSha256, backupRoot: result.backupRoot, receiptId });
}

export async function installRestrictedRuntime(
  config: RemoteSetupConfig,
  preflight: RemoteSetupPreflightReport,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteInstallResult> {
  if (!preflight.ok || !preflight.nodePath || !preflight.remote) throw new OpsHavenError("POLICY_DENIED", "Remote installation requires a successful preflight report.");
  const remotePolicyPath = `${config.policyConfigPath}.dispatcher.json`;
  await loadConfig(remotePolicyPath);
  const manifest = await buildRuntimeManifest(config.local.runtimeRoot);
  const receiptId = randomBytes(16).toString("hex");
  const stageRoot = await fs.mkdtemp(path.join(tmpdir(), `opshaven-setup-${receiptId}-`));
  const remoteStage = `/tmp/${path.basename(stageRoot)}`;
  try {
    const stageRuntime = path.join(stageRoot, "runtime");
    await fs.mkdir(stageRuntime, { recursive: true, mode: 0o700 });
    await copyRuntime(config.local.runtimeRoot, stageRuntime, manifest);
    const wrapperTemplate = await readRegularTextFile(config.local.wrapperTemplatePath, "Read-only wrapper template", { maxBytes: 65536, code: "POLICY_DENIED" });
    const wrapper = renderReadonlyWrapper(wrapperTemplate, preflight.nodePath, config.remote.runtimeRoot);
    const restrictedKey = await readRegularTextFile(config.local.restrictedAuthorizedKeyFile, "Restricted SSH public key", { maxBytes: 16384, code: "POLICY_DENIED" });
    const authorizedKey = buildRestrictedAuthorizedKey(restrictedKey, config.remote.wrapperPath, config.remote.configPath);
    const installerSource = path.join(process.cwd(), "packaging", "remote-setup-installer.py");
    const plan = {
      version: 1,
      receiptId,
      sourceSha: config.expectedSourceSha,
      nodePath: preflight.nodePath,
      stageRoot: remoteStage,
      account: config.remote.account,
      runtimeRoot: config.remote.runtimeRoot,
      configPath: config.remote.configPath,
      wrapperPath: config.remote.wrapperPath,
      stateDirectory: config.remote.stateDirectory,
      receiptPath: config.remote.receiptPath,
      runtimeManifest: "runtime-manifest.json",
      remoteConfig: "remote-config.json",
      wrapper: "wrapper",
      authorizedKeys: "authorized_keys",
    };
    await Promise.all([
      fs.writeFile(path.join(stageRoot, "runtime-manifest.json"), `${JSON.stringify(manifest)}\n`, { mode: 0o600 }),
      fs.copyFile(remotePolicyPath, path.join(stageRoot, "remote-config.json")),
      fs.writeFile(path.join(stageRoot, "wrapper"), wrapper, { mode: 0o700 }),
      fs.writeFile(path.join(stageRoot, "authorized_keys"), authorizedKey, { mode: 0o600 }),
      fs.copyFile(installerSource, path.join(stageRoot, "installer.py")),
      fs.writeFile(path.join(stageRoot, "plan.json"), `${JSON.stringify(plan)}\n`, { mode: 0o600 }),
    ]);
    const upload = await transport.upload(stageRoot, "/tmp", true);
    if (upload.code !== 0) throw new OpsHavenError("SSH_FAILED", "Remote setup staging upload failed.", true);
    const installed = await transport.runPrivileged(["/usr/bin/python3", `${remoteStage}/installer.py`, remoteStage], { timeoutMs: 180000, maximumBytes: 1048576 });
    if (installed.code !== 0) throw new OpsHavenError("SSH_FAILED", `Remote installer failed safely: ${installed.stderr.trim() || "no diagnostic"}.`, true);
    const result = parseInstallResult(installed.stdout, receiptId);
    if (result.runtimeTreeSha256 !== manifest.treeSha256) throw new OpsHavenError("POLICY_DENIED", "Installed runtime tree hash does not match the local manifest.");
    return result;
  } finally {
    await fs.rm(stageRoot, { recursive: true, force: true });
  }
}
