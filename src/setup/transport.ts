import { spawn } from "node:child_process";
import { OpsHavenError } from "../errors.js";
import type { RemoteSetupConfig } from "./remote.js";

export interface SetupCommandResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export interface SetupProcessOptions {
  readonly stdin?: string;
  readonly timeoutMs?: number;
  readonly maximumBytes?: number;
  readonly cwd?: string;
}

export interface RemoteAdminTransport {
  run(command: readonly string[], options?: SetupProcessOptions): Promise<SetupCommandResult>;
  runPrivileged(command: readonly string[], options?: SetupProcessOptions): Promise<SetupCommandResult>;
  runPython(script: string, privileged?: boolean): Promise<SetupCommandResult>;
  upload(localPath: string, remotePath: string, recursive?: boolean): Promise<SetupCommandResult>;
  download(remotePath: string, localPath: string): Promise<SetupCommandResult>;
}

const SAFE_REMOTE_TOKEN = /^[A-Za-z0-9_./:@+=,-]{1,4096}$/;
const SAFE_PATH = /^\/[A-Za-z0-9._/@+-]+(?:\/[A-Za-z0-9._@+-]+)*$/;

function target(config: RemoteSetupConfig): string {
  const host = config.target.host.includes(":") ? `[${config.target.host}]` : config.target.host;
  return `${config.target.adminUser}@${host}`;
}

function commonSshArgs(config: RemoteSetupConfig): string[] {
  return [
    "-T",
    "-p", String(config.target.port),
    "-i", config.target.identityFile,
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${config.target.knownHostsFile}`,
    "-o", "CheckHostIP=yes",
    "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "PermitLocalCommand=no",
    "-o", "RequestTTY=no",
    "-o", "ConnectTimeout=10",
    target(config),
  ];
}

function commonScpArgs(config: RemoteSetupConfig): string[] {
  return [
    "-P", String(config.target.port),
    "-i", config.target.identityFile,
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${config.target.knownHostsFile}`,
    "-o", "CheckHostIP=yes",
    "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "RequestTTY=no",
  ];
}

function validateRemoteCommand(command: readonly string[]): void {
  if (command.length === 0 || command.length > 64 || command.some((item) => !SAFE_REMOTE_TOKEN.test(item))) {
    throw new OpsHavenError("CONFIG_INVALID", "Remote setup command contains an unsafe token.");
  }
}

function validatePath(filePath: string, label: string): void {
  if (!SAFE_PATH.test(filePath) || filePath.includes("..")) throw new OpsHavenError("CONFIG_INVALID", `${label} is not a safe absolute path.`);
}

export async function runSetupProcess(command: string, args: readonly string[], options: SetupProcessOptions = {}): Promise<SetupCommandResult> {
  if (!command.startsWith("/")) throw new OpsHavenError("CONFIG_INVALID", "Setup executables must use fixed absolute paths.");
  const maximumBytes = options.maximumBytes ?? 1048576;
  const timeoutMs = options.timeoutMs ?? 30000;
  return await new Promise<SetupCommandResult>((resolve, reject) => {
    const child = spawn(command, args, {
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: "/usr/local/bin:/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    });
    const stdout: Uint8Array[] = [];
    const stderr: Uint8Array[] = [];
    let bytes = 0;
    let settled = false;
    const finish = (result: SetupCommandResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer as any);
      resolve(result);
    };
    const fail = (message: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer as any);
      child.kill("SIGKILL");
      reject(new OpsHavenError("SSH_FAILED", message, true));
    };
    const consume = (chunk: Uint8Array, output: Uint8Array[]): void => {
      bytes += chunk.length;
      if (bytes > maximumBytes) { fail("Setup process output exceeded its reviewed limit."); return; }
      output.push(chunk);
    };
    const timer = setTimeout(() => fail("Setup process timed out."), timeoutMs);
    child.stdout.on("data", (chunk: Uint8Array) => consume(chunk, stdout));
    child.stderr.on("data", (chunk: Uint8Array) => consume(chunk, stderr));
    child.on("error", () => fail("Setup process could not start."));
    child.on("close", (code: number | null) => finish({ code, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") }));
    (child.stdin as any).on?.("error", () => undefined);
    child.stdin.end(options.stdin ?? "");
  });
}

export class PinnedSshAdminTransport implements RemoteAdminTransport {
  constructor(private readonly config: RemoteSetupConfig) {}

  async run(command: readonly string[], options: SetupProcessOptions = {}): Promise<SetupCommandResult> {
    validateRemoteCommand(command);
    return await runSetupProcess("/usr/bin/ssh", [...commonSshArgs(this.config), ...command], options);
  }

  async runPrivileged(command: readonly string[], options: SetupProcessOptions = {}): Promise<SetupCommandResult> {
    const privileged = this.config.target.privilege === "root" ? [...command] : ["/usr/bin/sudo", "-n", ...command];
    return await this.run(privileged, options);
  }

  async runPython(script: string, privileged = false): Promise<SetupCommandResult> {
    if (Buffer.byteLength(script, "utf8") > 262144 || script.includes("\u0000")) throw new OpsHavenError("CONFIG_INVALID", "Remote setup Python input is invalid or oversized.");
    const command = ["/usr/bin/python3", "-"];
    return await (privileged ? this.runPrivileged(command, { stdin: script, timeoutMs: 30000 }) : this.run(command, { stdin: script, timeoutMs: 30000 }));
  }

  async upload(localPath: string, remotePath: string, recursive = false): Promise<SetupCommandResult> {
    validatePath(localPath, "Local upload path");
    validatePath(remotePath, "Remote upload path");
    const args = [...commonScpArgs(this.config), ...(recursive ? ["-r"] : []), localPath, `${target(this.config)}:${remotePath}`];
    return await runSetupProcess("/usr/bin/scp", args, { timeoutMs: 120000, maximumBytes: 1048576 });
  }

  async download(remotePath: string, localPath: string): Promise<SetupCommandResult> {
    validatePath(remotePath, "Remote download path");
    validatePath(localPath, "Local download path");
    return await runSetupProcess("/usr/bin/scp", [...commonScpArgs(this.config), `${target(this.config)}:${remotePath}`, localPath], { timeoutMs: 120000, maximumBytes: 1048576 });
  }
}
