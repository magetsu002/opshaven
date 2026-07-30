import { spawn } from "node:child_process";
import type { HostResource } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { verifyRegularFile } from "../safe-fs.js";
import type { RemoteRequest, RemoteResponse } from "../remote/protocol.js";
import { parseRemoteResponse } from "../remote/protocol.js";

export interface SpawnLike {
  (command: string, args: readonly string[], options: Record<string, unknown>): {
    stdin: { end(data: string): void };
    stdout: { on(event: string, listener: (chunk: Uint8Array) => void): void };
    stderr: { on(event: string, listener: (chunk: Uint8Array) => void): void };
    on(event: string, listener: (...args: any[]) => void): void;
    kill(signal?: string): void;
  };
}

export function buildSshArgs(host: HostResource): string[] {
  return [
    "-T",
    "-p", String(host.port),
    "-i", host.identityFile,
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${host.knownHostsFile}`,
    "-o", "CheckHostIP=yes",
    "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "PermitLocalCommand=no",
    "-o", "RequestTTY=no",
    "-o", `ConnectTimeout=${Math.ceil(host.connectTimeoutMs / 1000)}`,
    `${host.user}@${host.address}`,
  ];
}

function hostKeyFailure(stderr: string): boolean {
  return /REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed|No .* host key is known|Offending .* key/i.test(stderr);
}

export class SshTransport {
  constructor(private readonly spawnProcess: SpawnLike = spawn as unknown as SpawnLike) {}

  async execute(host: HostResource, request: RemoteRequest): Promise<RemoteResponse> {
    await verifyRegularFile(host.identityFile, "SSH identity", { ownerOnly: true, maxBytes: 65536, code: "SSH_FAILED" });
    await verifyRegularFile(host.knownHostsFile, "SSH known-hosts file", { maxBytes: 1048576, code: "SSH_HOST_KEY_FAILED" });
    const payload = `${JSON.stringify(request)}\n`;
    if (Buffer.byteLength(payload, "utf8") > 65536) throw new OpsHavenError("OUTPUT_LIMIT", "Remote request exceeds the protocol limit.");
    return await new Promise<RemoteResponse>((resolve, reject) => {
      const child = this.spawnProcess("/usr/bin/ssh", buildSshArgs(host), { shell: false, stdio: ["pipe", "pipe", "pipe"], env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" } });
      const stdout: Uint8Array[] = [];
      const stderr: Uint8Array[] = [];
      let bytes = 0;
      let lines = 0;
      let settled = false;
      const finishReject = (error: OpsHavenError): void => {
        if (settled) return;
        settled = true;
        reject(error);
      };
      const consume = (chunk: Uint8Array, collect: Uint8Array[]): void => {
        bytes += chunk.length;
        lines += Buffer.from(chunk).toString("utf8").split("\n").length - 1;
        if (bytes > request.limits.maxBytes || lines > request.limits.maxLines) {
          child.kill("SIGKILL");
          finishReject(new OpsHavenError("OUTPUT_LIMIT", "SSH output exceeded its configured limit."));
          return;
        }
        collect.push(chunk);
      };
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        finishReject(new OpsHavenError("TIMEOUT", "SSH operation timed out.", true));
      }, request.limits.timeoutMs);
      child.stdout.on("data", (chunk) => consume(chunk, stdout));
      child.stderr.on("data", (chunk) => consume(chunk, stderr));
      child.on("error", () => {
        clearTimeout(timer as any);
        finishReject(new OpsHavenError("SSH_FAILED", "SSH transport could not start.", true));
      });
      child.on("close", (code: number | null) => {
        clearTimeout(timer as any);
        if (settled) return;
        const stderrText = Buffer.concat(stderr).toString("utf8");
        if (stderrText.includes("\u0000")) return finishReject(new OpsHavenError("BINARY_OUTPUT", "Binary SSH output was rejected."));
        if (code !== 0) {
          const keyFailure = code === 255 && hostKeyFailure(stderrText);
          finishReject(new OpsHavenError(keyFailure ? "SSH_HOST_KEY_FAILED" : "SSH_FAILED", keyFailure ? "SSH host-key verification failed." : "Restricted SSH operation failed.", true));
          return;
        }
        try {
          const text = Buffer.concat(stdout).toString("utf8");
          if (text.includes("\u0000")) throw new OpsHavenError("BINARY_OUTPUT", "Binary SSH output was rejected.");
          const parsed = JSON.parse(text) as unknown;
          settled = true;
          resolve(parseRemoteResponse(parsed, request.requestId));
        } catch (error) {
          finishReject(error instanceof OpsHavenError ? error : new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote response was not valid JSON."));
        }
      });
      (child.stdin as any).on?.("error", () => undefined);
      child.stdin.end(payload);
    });
  }
}
