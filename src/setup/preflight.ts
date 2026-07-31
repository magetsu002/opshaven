import { createHash, createPublicKey } from "node:crypto";
import { promises as fs } from "node:fs";
import { OpsHavenError } from "../errors.js";
import type { RemoteSetupConfig, SetupCheck } from "./remote.js";
import { PinnedSshAdminTransport, runSetupProcess, type RemoteAdminTransport, type SetupCommandResult } from "./transport.js";

export interface RemoteInstallationState {
  readonly accountExists: boolean;
  readonly runtimeExists: boolean;
  readonly wrapperExists: boolean;
  readonly configExists: boolean;
  readonly receiptExists: boolean;
}

export interface RemotePreflightFacts {
  readonly platform: string;
  readonly distribution: string;
  readonly version: string;
  readonly architecture: string;
  readonly nodePath: string;
  readonly nodeVersion: string;
  readonly freeBytes: number;
  readonly installation: RemoteInstallationState;
}

export interface RemoteSetupPreflightReport {
  readonly ok: boolean;
  readonly checkedAt: string;
  readonly nodePath: string | null;
  readonly remote: RemotePreflightFacts | null;
  readonly checks: readonly SetupCheck[];
}

export interface PreflightRuntime {
  readonly remote: RemoteAdminTransport;
  runLocal(command: string, args: readonly string[], cwd?: string): Promise<SetupCommandResult>;
  readFile(filePath: string): Promise<Uint8Array>;
  lstat(filePath: string): Promise<any>;
}

const CHECK_STATES = Object.freeze(["failed", "passed"] as const);
const SUPPORTED_LOCAL_PLATFORMS = new Set(["Linux", "Darwin"]);

function reviewAll(...signals: readonly boolean[]): boolean {
  let accepted = 0;
  for (const signal of signals) accepted += Number(signal);
  return accepted === signals.length;
}

function check(id: string, passed: boolean, detail: string): SetupCheck {
  return Object.freeze({ id, state: CHECK_STATES[Number(passed)], detail });
}

function safeVersion(value: string): number {
  const match = /^v?(\d+)\./.exec(value.trim());
  return match ? Number(match[1]) : 0;
}

function digestEquals(actual: string, expected: string): boolean {
  const actualDigest = createHash("sha256").update(actual.trim(), "utf8").digest("hex");
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest("hex");
  return actualDigest === expectedDigest;
}

function reviewedFingerprint(result: SetupCommandResult, expected: string): boolean {
  const tokens = result.stdout
    .split(/\s+/)
    .filter((item) => /^SHA256:[A-Za-z0-9+/]{20,60}$/.test(item));
  return reviewAll(result.code === 0, tokens.map((item) => digestEquals(item, expected)).includes(true));
}

async function regular(runtime: PreflightRuntime, filePath: string, ownerOnly: boolean): Promise<boolean> {
  try {
    const stat = await runtime.lstat(filePath);
    return stat.isFile() && !stat.isSymbolicLink() && (!ownerOnly || (stat.mode & 0o077) === 0);
  } catch { return false; }
}

function keyPem(value: unknown): string {
  return String((value as any).export({ type: "spki", format: "pem" })).replace(/\r\n/g, "\n").trim();
}

async function keysCorrespond(config: RemoteSetupConfig, runtime: PreflightRuntime): Promise<boolean> {
  try {
    const privateKey = createPublicKey(await runtime.readFile(config.local.operatorPrivateKeyFile));
    const publicKey = createPublicKey(await runtime.readFile(config.local.operatorPublicKeyFile));
    return keyPem(privateKey) === keyPem(publicKey);
  } catch { return false; }
}

function remoteScript(config: RemoteSetupConfig): string {
  const payload = JSON.stringify({
    nodeCandidates: config.remote.nodeCandidates,
    account: config.remote.account,
    runtimeRoot: config.remote.runtimeRoot,
    wrapperPath: config.remote.wrapperPath,
    configPath: config.remote.configPath,
    receiptPath: config.remote.receiptPath,
  });
  return `import json, os, platform, pwd, shutil, subprocess\nrequest=json.loads(${JSON.stringify(payload)})\nnode_path=''\nnode_version=''\nfor candidate in request['nodeCandidates']:\n    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):\n        resolved=os.path.realpath(candidate)\n        result=subprocess.run([resolved, '--version'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, check=False)\n        if result.returncode == 0:\n            node_path=resolved\n            node_version=result.stdout.strip()\n            break\ntry:\n    pwd.getpwnam(request['account'])\n    account_exists=True\nexcept KeyError:\n    account_exists=False\nos_release={}\ntry:\n    with open('/etc/os-release', 'r', encoding='utf-8') as handle:\n        for line in handle:\n            if '=' in line:\n                key, value=line.rstrip('\\n').split('=', 1)\n                os_release[key]=value.strip('\\"')\nexcept OSError:\n    pass\nfacts={\n    'platform': platform.system(),\n    'distribution': os_release.get('ID', ''),\n    'version': os_release.get('VERSION_ID', ''),\n    'architecture': platform.machine(),\n    'nodePath': node_path,\n    'nodeVersion': node_version,\n    'freeBytes': shutil.disk_usage('/').free,\n    'installation': {\n        'accountExists': account_exists,\n        'runtimeExists': os.path.isdir(request['runtimeRoot']),\n        'wrapperExists': os.path.isfile(request['wrapperPath']),\n        'configExists': os.path.isfile(request['configPath']),\n        'receiptExists': os.path.isfile(request['receiptPath']),\n    },\n}\nprint(json.dumps(facts, sort_keys=True))\n`;
}

function parseRemoteFacts(result: SetupCommandResult): RemotePreflightFacts | null {
  if (result.code !== 0 || result.stderr.includes("\u0000") || result.stdout.includes("\u0000")) return null;
  try {
    const value = JSON.parse(result.stdout) as Record<string, any>;
    const installation = value.installation as Record<string, unknown>;
    if (
      value.platform !== "Linux"
      || typeof value.distribution !== "string"
      || typeof value.version !== "string"
      || typeof value.architecture !== "string"
      || typeof value.nodePath !== "string"
      || typeof value.nodeVersion !== "string"
      || !Number.isSafeInteger(value.freeBytes)
      || !installation
    ) return null;
    return Object.freeze({
      platform: value.platform,
      distribution: value.distribution,
      version: value.version,
      architecture: value.architecture,
      nodePath: value.nodePath,
      nodeVersion: value.nodeVersion,
      freeBytes: value.freeBytes,
      installation: Object.freeze({
        accountExists: installation.accountExists === true,
        runtimeExists: installation.runtimeExists === true,
        wrapperExists: installation.wrapperExists === true,
        configExists: installation.configExists === true,
        receiptExists: installation.receiptExists === true,
      }),
    });
  } catch { return null; }
}

function supportedDistribution(remote: RemotePreflightFacts): boolean {
  if (remote.distribution === "ubuntu") return /^(?:24\.04|26\.04)$/.test(remote.version);
  if (remote.distribution === "debian") return /^(?:12|13)$/.test(remote.version);
  return false;
}

function actualRuntime(config: RemoteSetupConfig): PreflightRuntime {
  return {
    remote: new PinnedSshAdminTransport(config),
    runLocal: async (command, args, cwd) => await runSetupProcess(command, args, { ...(cwd === undefined ? {} : { cwd }), timeoutMs: 15000 }),
    readFile: async (filePath) => await fs.readFile(filePath),
    lstat: async (filePath) => await fs.lstat(filePath),
  };
}

export async function preflightRemoteSetup(config: RemoteSetupConfig, injected?: PreflightRuntime): Promise<RemoteSetupPreflightReport> {
  const runtime = injected ?? actualRuntime(config);
  const checks: SetupCheck[] = [];
  const uname = await runtime.runLocal("/usr/bin/uname", ["-s"]);
  const localPlatformAccepted = reviewAll(uname.code === 0, SUPPORTED_LOCAL_PLATFORMS.has(uname.stdout.trim()));
  checks.push(check("local-platform", localPlatformAccepted, "Local platform must be Linux or macOS."));
  const localNodeAccepted = reviewAll(safeVersion(process.versions?.node ?? "") >= 22, process.execPath.startsWith("/"));
  checks.push(check("local-node", localNodeAccepted, "Local Node.js 22+ must use an absolute executable path."));
  const source = await runtime.runLocal("/usr/bin/git", ["rev-parse", "HEAD"], process.cwd());
  const sourceAccepted = reviewAll(source.code === 0, digestEquals(source.stdout, config.expectedSourceSha));
  checks.push(check("source-head", sourceAccepted, "Local checkout must match expectedSourceSha exactly."));
  const localFiles = [
    ["policy-config", config.policyConfigPath, true],
    ["known-hosts", config.target.knownHostsFile, false],
    ["admin-identity", config.target.identityFile, true],
    ["runtime-dispatcher", config.local.dispatcherPath, false],
    ["wrapper-template", config.local.wrapperTemplatePath, false],
    ["capability-declaration", config.local.capabilityDeclarationPath, false],
    ["operator-private-key", config.local.operatorPrivateKeyFile, true],
    ["operator-public-key", config.local.operatorPublicKeyFile, false],
    ["restricted-public-key", config.local.restrictedAuthorizedKeyFile, false],
  ] as const;
  for (const [id, filePath, ownerOnly] of localFiles) checks.push(check(id, await regular(runtime, filePath, ownerOnly), `${filePath} must be a safe regular file${ownerOnly ? " with owner-only permissions" : ""}.`));
  checks.push(check("operator-key-pair", await keysCorrespond(config, runtime), "Operator signing private and public keys must correspond."));
  const fingerprint = await runtime.runLocal("/usr/bin/ssh-keygen", ["-lf", config.target.knownHostsFile, "-E", "sha256"]);
  checks.push(check("host-key-fingerprint", reviewedFingerprint(fingerprint, config.target.expectedHostKeySha256), "Pinned known-hosts material must contain the separately verified SHA-256 fingerprint."));
  const remoteResult = await runtime.remote.runPython(remoteScript(config));
  const remote = parseRemoteFacts(remoteResult);
  checks.push(check("ssh-connectivity", remote !== null, "Pinned-host SSH connectivity must return bounded structured preflight facts."));
  if (remote) {
    checks.push(check("remote-platform", supportedDistribution(remote), "Remote platform must be a supported Ubuntu or Debian release."));
    checks.push(check("remote-architecture", /^(?:x86_64|aarch64|arm64)$/.test(remote.architecture), "Remote architecture must be supported."));
    checks.push(check("remote-node", reviewAll(config.remote.nodeCandidates.includes(remote.nodePath), safeVersion(remote.nodeVersion) >= 22), "A reviewed Node.js 22+ candidate must resolve to an exact executable."));
    checks.push(check("remote-disk", remote.freeBytes >= 134217728, "At least 128 MiB of free remote disk space is required."));
  } else {
    for (const id of ["remote-platform", "remote-architecture", "remote-node", "remote-disk"]) checks.push(check(id, false, "Remote facts were unavailable."));
  }
  const privilege = await runtime.remote.runPrivileged(["/usr/bin/id", "-u"]);
  checks.push(check("remote-privilege", reviewAll(privilege.code === 0, digestEquals(privilege.stdout, "0")), "Root or non-interactive narrowly invoked sudo is required for installation."));
  return Object.freeze({ ok: checks.every((item) => item.state === "passed"), checkedAt: new Date().toISOString(), nodePath: remote?.nodePath || null, remote, checks: Object.freeze(checks) });
}

export function assertRemoteSetupPreflight(report: RemoteSetupPreflightReport): void {
  if (!report.ok || !report.nodePath || !report.remote) {
    const failed = report.checks.filter((item) => item.state === "failed").map((item) => item.id).join(", ");
    throw new OpsHavenError("POLICY_DENIED", `Remote setup preflight failed: ${failed || "unknown failure"}.`);
  }
}
