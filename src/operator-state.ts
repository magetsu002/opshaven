import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { parseConfig } from "./config.js";
import { OpsHavenError } from "./errors.js";
import { parseRemoteSetupConfig } from "./setup/remote.js";

interface StateDocument {
  version: 1;
  initializedAt: string;
  remoteConfigured: boolean;
  target?: { host: string; port: number; adminUser: string };
}

interface Paths {
  root: string;
  state: string;
  policy: string;
  setup: string;
  keys: string;
  operatorPrivate: string;
  operatorPublic: string;
  restrictedPrivate: string;
  restrictedPublic: string;
  approvalSecret: string;
  approvals: string;
  remoteUsed: string;
  audit: string;
}

interface Answers {
  host: string;
  port: number;
  adminUser: string;
  adminIdentity: string;
  knownHosts: string;
  fingerprint: string;
  privilege: "root" | "sudo-noninteractive";
  sourceSha: string;
}

export interface OperatorStateSnapshot {
  initialized: boolean;
  keysReady: boolean;
  localConfigurationReady: boolean;
  remoteConfigured: boolean;
  setupReady: boolean;
  configPath: string | null;
  setupPath: string | null;
}

type LocalCommand = "git" | "ssh-keygen";

const MAX_OUTPUT = 65536;
const HOST = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|[0-9A-Fa-f:]+)$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{20,60}$/;
const SHA = /^[a-f0-9]{40}$/;

function flag(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}

function absolute(value: string, label: string): string {
  const home = process.env.HOME ?? "";
  const expanded = value === "~" ? home : value.startsWith("~/") ? path.join(home, value.slice(2)) : value;
  if (!path.isAbsolute(expanded) || path.normalize(expanded) !== expanded || expanded.includes("..")) {
    throw new OpsHavenError("CONFIG_INVALID", `${label} must be a normalized absolute path.`);
  }
  return expanded;
}

export function operatorStateRoot(): string {
  const home = homedir();
  if (!home || !path.isAbsolute(home) || path.normalize(home) !== home) {
    throw new OpsHavenError("CONFIG_INVALID", "A local operator home directory could not be determined.");
  }
  return path.join(home, ".config", "opshaven");
}

function locations(): Paths {
  const root = operatorStateRoot();
  const keys = path.join(root, "keys");
  return {
    root,
    state: path.join(root, "state.json"),
    policy: path.join(root, "config.json"),
    setup: path.join(root, "setup.json"),
    keys,
    operatorPrivate: path.join(keys, "operator-private.pem"),
    operatorPublic: path.join(keys, "operator-public.pem"),
    restrictedPrivate: path.join(keys, "restricted-ssh"),
    restrictedPublic: path.join(keys, "restricted-ssh.pub"),
    approvalSecret: path.join(keys, "approval-secret"),
    approvals: path.join(root, "approvals"),
    remoteUsed: path.join(root, "remote-used"),
    audit: path.join(root, "audit.jsonl"),
  };
}

function packageRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
}

async function run(command: LocalCommand, args: readonly string[], cwd?: string): Promise<{ code: number | null; stdout: string }> {
  const executable = command === "git" ? "/usr/bin/git" : "/usr/bin/ssh-keygen";
  const child = spawn(executable, args, {
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    ...(cwd ? { cwd } : {}),
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
  });
  return await new Promise((resolve, reject) => {
    let stdout = "";
    let total = 0;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new OpsHavenError("TIMEOUT", "A local setup command timed out."));
    }, 15000);
    const collect = (chunk: Uint8Array): void => {
      total += chunk.length;
      if (total > MAX_OUTPUT) child.kill("SIGKILL");
      else stdout += Buffer.from(chunk).toString("utf8");
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", (chunk: Uint8Array) => {
      total += chunk.length;
      if (total > MAX_OUTPUT) child.kill("SIGKILL");
    });
    child.on("error", (error: unknown) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code: number | null) => {
      clearTimeout(timer);
      if (total > MAX_OUTPUT) reject(new OpsHavenError("OUTPUT_LIMIT", "A local setup command exceeded its output limit."));
      else resolve({ code, stdout });
    });
  });
}

async function privateDirectory(directory: string): Promise<void> {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new OpsHavenError("CONFIG_INVALID", "Operator state contains an unsafe directory.");
  await fs.chmod(directory, 0o700);
}

async function safeFile(file: string, ownerOnly: boolean): Promise<boolean> {
  try {
    const stat = await fs.lstat(file);
    return stat.isFile() && !stat.isSymbolicLink() && (!ownerOnly || (stat.mode & 0o077) === 0);
  } catch {
    return false;
  }
}

async function write(file: string, value: string | Uint8Array, mode: number): Promise<void> {
  const temporary = `${file}.opshaven-${process.pid}-${Date.now()}`;
  try {
    await fs.writeFile(temporary, value, { mode, flag: "wx" });
    await fs.chmod(temporary, mode);
    await fs.rename(temporary, file);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

function publicPem(key: unknown): string {
  return String((key as any).export({ type: "spki", format: "pem" })).replace(/\r\n/g, "\n").trim();
}

async function ensureKeys(paths: Paths): Promise<void> {
  const privateReady = await safeFile(paths.operatorPrivate, true);
  const publicReady = await safeFile(paths.operatorPublic, false);
  if (privateReady !== publicReady) throw new OpsHavenError("CONFIG_INVALID", "Local authorization key state is incomplete.");
  if (!privateReady) {
    const pair = generateKeyPairSync("ed25519");
    await write(paths.operatorPrivate, pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string, 0o600);
    await write(paths.operatorPublic, pair.publicKey.export({ type: "spki", format: "pem" }) as string, 0o644);
  } else {
    try {
      if (publicPem(createPublicKey(await fs.readFile(paths.operatorPrivate))) !== publicPem(createPublicKey(await fs.readFile(paths.operatorPublic)))) throw new Error("mismatch");
    } catch {
      throw new OpsHavenError("CONFIG_INVALID", "Local authorization keys do not correspond.");
    }
  }
  if (!(await safeFile(paths.approvalSecret, true))) await write(paths.approvalSecret, randomBytes(32), 0o600);

  const restrictedPrivate = await safeFile(paths.restrictedPrivate, true);
  const restrictedPublic = await safeFile(paths.restrictedPublic, false);
  if (restrictedPrivate !== restrictedPublic) throw new OpsHavenError("CONFIG_INVALID", "Restricted SSH key state is incomplete.");
  if (!restrictedPrivate) {
    try {
      const result = await run("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "opshaven-restricted", "-f", paths.restrictedPrivate]);
      if (result.code !== 0) throw new Error("failed");
    } catch {
      throw new OpsHavenError("CONFIG_INVALID", "OpenSSH key generation is unavailable.");
    }
    await fs.chmod(paths.restrictedPrivate, 0o600);
    await fs.chmod(paths.restrictedPublic, 0o644);
  }
}

async function readState(paths: Paths): Promise<StateDocument | null> {
  if (!(await safeFile(paths.state, true))) return null;
  try {
    const state = JSON.parse(await fs.readFile(paths.state, "utf8")) as StateDocument;
    if (state.version !== 1 || typeof state.initializedAt !== "string" || typeof state.remoteConfigured !== "boolean") throw new Error("invalid");
    return state;
  } catch {
    throw new OpsHavenError("CONFIG_INVALID", "Operator setup state is missing or outdated.");
  }
}

async function saveState(paths: Paths, state: StateDocument): Promise<void> {
  await write(paths.state, `${JSON.stringify(state, null, 2)}\n`, 0o600);
}

async function ask(question: string, fallback = ""): Promise<string> {
  const input = createInterface({ input: process.stdin, output: process.stderr });
  return await new Promise((resolve) => input.question(`${question}${fallback ? ` [${fallback}]` : ""}: `, (answer: string) => {
    input.close();
    resolve(answer.trim() || fallback);
  }));
}

function port(value: string | undefined): number {
  const parsed = value === undefined ? 22 : Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) throw new OpsHavenError("CONFIG_INVALID", "Remote SSH port is invalid.");
  return parsed;
}

async function sourceSha(args: readonly string[]): Promise<string> {
  const supplied = flag(args, "--source-sha") ?? process.env.OPSHAVEN_SOURCE_SHA;
  if (supplied && SHA.test(supplied)) return supplied;
  try {
    const result = await run("git", ["rev-parse", "HEAD"], packageRoot());
    const discovered = result.stdout.trim();
    if (result.code === 0 && SHA.test(discovered)) return discovered;
  } catch {}
  throw new OpsHavenError("CONFIG_INVALID", "Verified OpsHaven source identity is unavailable. Run from a checked-out release or pass --source-sha <commit>.");
}

async function collectAnswers(args: readonly string[]): Promise<Answers | null> {
  if (args.includes("--local-only")) return null;
  const interactive = (process.stdin as any).isTTY === true && !args.includes("--non-interactive");
  let host = flag(args, "--host") ?? "";
  let fingerprint = flag(args, "--host-key-sha256") ?? "";
  if (!host && !fingerprint && !interactive) return null;
  if (!host && interactive) host = await ask("Remote host");
  if (!fingerprint && interactive) fingerprint = await ask("Verified SSH host-key fingerprint");
  if (!HOST.test(host) || !FINGERPRINT.test(fingerprint)) throw new OpsHavenError("CONFIG_INVALID", "Remote deployment details are incomplete or invalid.");

  const home = process.env.HOME ?? "";
  const adminUser = flag(args, "--admin-user") ?? (interactive ? await ask("Administrator SSH user", "root") : "root");
  if (!USER.test(adminUser)) throw new OpsHavenError("CONFIG_INVALID", "Administrator SSH user is invalid.");
  const defaultIdentity = home ? path.join(home, ".ssh", "id_ed25519") : "";
  const defaultKnownHosts = home ? path.join(home, ".ssh", "known_hosts") : "";
  const adminIdentity = flag(args, "--admin-identity") ?? (interactive ? await ask("Administrator SSH private key", defaultIdentity) : defaultIdentity);
  const knownHosts = flag(args, "--known-hosts") ?? (interactive ? await ask("Pinned known-hosts file", defaultKnownHosts) : defaultKnownHosts);
  if (!adminIdentity || !knownHosts) throw new OpsHavenError("CONFIG_INVALID", "Remote deployment details are not configured.");
  const privilege = flag(args, "--privilege") ?? (adminUser === "root" ? "root" : "sudo-noninteractive");
  if (privilege !== "root" && privilege !== "sudo-noninteractive") throw new OpsHavenError("CONFIG_INVALID", "Remote privilege is invalid.");
  return { host, port: port(flag(args, "--port")), adminUser, adminIdentity: absolute(adminIdentity, "Administrator SSH private key"), knownHosts: absolute(knownHosts, "Pinned known-hosts file"), fingerprint, privilege, sourceSha: await sourceSha(args) };
}

function common() {
  return { version: 1 as const, policyVersion: "operator-v1", limits: { timeoutMs: 15000, maxBytes: 131072, maxLines: 1000 }, secretFingerprints: [] as string[] };
}

async function configure(paths: Paths, answers: Answers): Promise<void> {
  if (!(await safeFile(answers.adminIdentity, true)) || !(await safeFile(answers.knownHosts, false))) throw new OpsHavenError("CONFIG_INVALID", "Administrator SSH identity or pinned host-key file is unavailable.");
  const local = {
    ...common(),
    audit: { path: paths.audit },
    approvals: { directory: paths.approvals, secretFile: paths.approvalSecret, signingPrivateKeyFile: paths.operatorPrivate, verificationPublicKeyFile: paths.operatorPublic, remoteUsedDirectory: paths.remoteUsed, defaultTtlSeconds: 300 },
    resources: [{ id: "host.primary", kind: "host", address: answers.host, port: answers.port, user: "opshaven", knownHostsFile: answers.knownHosts, identityFile: paths.restrictedPrivate, connectTimeoutMs: 5000 }],
  };
  const remote = {
    ...common(),
    audit: { path: "/var/lib/opshaven/audit.jsonl" },
    approvals: { directory: "/var/lib/opshaven/unused-approvals", secretFile: "/var/lib/opshaven/unused-secret", signingPrivateKeyFile: "/var/lib/opshaven/unused-private", verificationPublicKeyFile: "/etc/opshaven/approval-public.pem", remoteUsedDirectory: "/var/lib/opshaven/remote-used", defaultTtlSeconds: 300 },
    resources: [{ id: "host.primary", kind: "host", address: "localhost", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/unused-known-hosts", identityFile: "/etc/opshaven/unused-identity", connectTimeoutMs: 5000 }],
  };
  parseConfig(local);
  parseConfig(remote);
  const root = packageRoot();
  const setup = parseRemoteSetupConfig({
    version: 1,
    policyConfigPath: paths.policy,
    expectedSourceSha: answers.sourceSha,
    target: { host: answers.host, port: answers.port, adminUser: answers.adminUser, knownHostsFile: answers.knownHosts, identityFile: answers.adminIdentity, expectedHostKeySha256: answers.fingerprint, privilege: answers.privilege },
    local: { runtimeRoot: path.join(root, "dist-readonly"), dispatcherPath: path.join(root, "dist-readonly/src/remote/read-only-dispatcher.js"), wrapperTemplatePath: path.join(root, "packaging/opshaven-readonly-force-command"), capabilityDeclarationPath: path.join(root, "security/capability-declaration.json"), operatorPrivateKeyFile: paths.operatorPrivate, operatorPublicKeyFile: paths.operatorPublic, restrictedAuthorizedKeyFile: paths.restrictedPublic },
    remote: { account: "opshaven", runtimeRoot: "/usr/lib/opshaven", configPath: "/etc/opshaven/config.json", wrapperPath: "/usr/local/bin/opshaven-readonly-force-command", stateDirectory: "/var/lib/opshaven", receiptPath: "/var/lib/opshaven/setup-receipt.json", nodeCandidates: ["/usr/local/bin/node", "/usr/bin/node"] },
    trust: { expiresInSeconds: 3600 },
  });
  await write(paths.policy, `${JSON.stringify(local, null, 2)}\n`, 0o600);
  await write(`${paths.policy}.dispatcher.json`, `${JSON.stringify(remote, null, 2)}\n`, 0o600);
  await write(paths.setup, `${JSON.stringify(setup, null, 2)}\n`, 0o600);
  const previous = await readState(paths);
  await saveState(paths, { version: 1, initializedAt: previous?.initializedAt ?? new Date().toISOString(), remoteConfigured: true, target: { host: answers.host, port: answers.port, adminUser: answers.adminUser } });
}

export async function runInit(args: readonly string[]): Promise<void> {
  const paths = locations();
  for (const directory of [paths.root, paths.keys, paths.approvals, paths.remoteUsed]) await privateDirectory(directory);
  await ensureKeys(paths);
  const previous = await readState(paths);
  if (!previous) await saveState(paths, { version: 1, initializedAt: new Date().toISOString(), remoteConfigured: false });
  const answers = await collectAnswers(args);
  if (answers) await configure(paths, answers);
  const result = { ok: true, state: answers || previous?.remoteConfigured ? "REMOTE_CONFIGURED" : "LOCAL_INITIALIZED", next: "opshaven setup remote" };
  if (args.includes("--json")) process.stdout.write(`${JSON.stringify(result)}\n`);
  else process.stdout.write("OpsHaven first-time setup\n\n✓ Operator environment detected\n✓ Local authorization keys prepared\n✓ Setup state created\n\nSecurity boundary:\nPrivate authorization and SSH keys remain on this machine. Remote setup uploads only public verification material and the reviewed read-only runtime.\n\nNext:\nopshaven setup remote\n");
}

export async function ensureRemoteSetupState(args: readonly string[]): Promise<string> {
  const paths = locations();
  if (await safeFile(paths.setup, true)) return paths.setup;
  if (!(await readState(paths))) throw new OpsHavenError("CONFIG_INVALID", "Setup is not initialized.");
  const answers = await collectAnswers(args);
  if (!answers) throw new OpsHavenError("CONFIG_INVALID", "Remote deployment details are not configured.");
  await configure(paths, answers);
  return paths.setup;
}

export async function resolveLocalConfigPath(args: readonly string[] = process.argv.slice(2)): Promise<string | null> {
  const explicit = flag(args, "--config") ?? process.env.OPSHAVEN_CONFIG;
  if (explicit) return absolute(explicit, "Configuration path");
  try {
    const paths = locations();
    return await safeFile(paths.policy, true) ? paths.policy : null;
  } catch {
    return null;
  }
}

export async function resolveSetupConfigPath(args: readonly string[] = process.argv.slice(2)): Promise<string | null> {
  const explicit = flag(args, "--setup-config") ?? process.env.OPSHAVEN_SETUP_CONFIG;
  if (explicit) return absolute(explicit, "Setup state path");
  try {
    const paths = locations();
    return await safeFile(paths.setup, true) ? paths.setup : null;
  } catch {
    return null;
  }
}

export async function inspectOperatorState(_args: readonly string[] = process.argv.slice(2)): Promise<OperatorStateSnapshot> {
  const paths = locations();
  let state: StateDocument | null = null;
  try { state = await readState(paths); } catch {}
  const initialized = state !== null;
  const keysReady = initialized
    && await safeFile(paths.operatorPrivate, true)
    && await safeFile(paths.operatorPublic, false)
    && await safeFile(paths.restrictedPrivate, true)
    && await safeFile(paths.restrictedPublic, false)
    && await safeFile(paths.approvalSecret, true);
  const policyReady = await safeFile(paths.policy, true);
  const setupReady = await safeFile(paths.setup, true);
  return { initialized, keysReady, localConfigurationReady: initialized && (state?.remoteConfigured === false || policyReady), remoteConfigured: state?.remoteConfigured === true, setupReady, configPath: policyReady ? paths.policy : null, setupPath: setupReady ? paths.setup : null };
}
