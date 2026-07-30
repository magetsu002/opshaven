import { spawn } from "node:child_process";
import { OpsHavenError } from "../core/errors.js";
import type { OutputBounds } from "../core/types.js";

export type ProcessRequest = Readonly<{
  executable: string;
  args: readonly string[];
  stdin?: Uint8Array;
  timeoutMs: number;
  output: OutputBounds;
  cwd?: string;
}>;

export type ProcessResult = Readonly<{
  exitCode: number;
  stdout: Uint8Array;
  stderr: Uint8Array;
}>;

export type ProcessRunner = (request: ProcessRequest) => Promise<ProcessResult>;

function enforceBounds(stdout: Buffer, stderr: Buffer, bounds: OutputBounds): void {
  const totalBytes = stdout.byteLength + stderr.byteLength;
  const totalLines = stdout.toString("utf8").split("\n").length + stderr.toString("utf8").split("\n").length;
  if (totalBytes > bounds.maxBytes || totalLines > bounds.maxLines) {
    throw new OpsHavenError("OUTPUT_LIMIT_EXCEEDED", "Subprocess output exceeded configured bounds", {
      totalBytes,
      totalLines,
      maxBytes: bounds.maxBytes,
      maxLines: bounds.maxLines
    });
  }
}

export const runProcess: ProcessRunner = async (request) =>
  await new Promise<ProcessResult>((resolve, reject) => {
    const child = spawn(request.executable, [...request.args], {
      cwd: request.cwd,
      env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
      shell: false,
      stdio: ["pipe", "pipe", "pipe"]
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let settled = false;

    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill("SIGKILL");
      reject(error);
    };

    const collect = (target: Buffer[], chunk: Buffer): void => {
      target.push(chunk);
      try {
        enforceBounds(Buffer.concat(stdout), Buffer.concat(stderr), request.output);
      } catch (error) {
        fail(error);
      }
    };

    child.stdout.on("data", (chunk: Buffer) => collect(stdout, chunk));
    child.stderr.on("data", (chunk: Buffer) => collect(stderr, chunk));
    child.once("error", (error) => fail(new OpsHavenError("OPERATION_FAILED", error.message)));
    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ exitCode: code ?? 255, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });

    const timer = setTimeout(() => {
      fail(new OpsHavenError("SSH_TIMEOUT", "Subprocess timed out", { timeoutMs: request.timeoutMs }));
    }, request.timeoutMs);
    timer.unref();

    if (request.stdin !== undefined) child.stdin.end(request.stdin);
    else child.stdin.end();
  });
