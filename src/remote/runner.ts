import { spawn } from "node:child_process";
import { OpsHavenError } from "../errors.js";

export interface RunOptions { cwd?: string; timeoutMs: number; maxBytes: number; maxLines: number; stdin?: string }
export interface RunResult { stdout: string; exitCode: number }
export interface CommandRunner { run(executable: string, args: readonly string[], options: RunOptions): Promise<RunResult> }

export class FixedCommandRunner implements CommandRunner {
  async run(executable: string, args: readonly string[], options: RunOptions): Promise<RunResult> {
    if (!executable.startsWith("/") || args.some((arg) => arg.includes("\u0000"))) throw new OpsHavenError("POLICY_DENIED", "Unsafe command specification rejected.");
    return await new Promise<RunResult>((resolve, reject) => {
      const child = spawn(executable, args, { shell: false, cwd: options.cwd, stdio: ["pipe", "pipe", "pipe"], env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" } });
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      let lines = 0;
      let settled = false;
      const fail = (error: OpsHavenError): void => { if (!settled) { settled = true; reject(error); } };
      const timer = setTimeout(() => { child.kill("SIGKILL"); fail(new OpsHavenError("TIMEOUT", "Remote command timed out.", true)); }, options.timeoutMs);
      child.stdout.on("data", (chunk: Uint8Array) => {
        bytes += chunk.length;
        lines += Buffer.from(chunk).toString("utf8").split("\n").length - 1;
        if (bytes > options.maxBytes || lines > options.maxLines) {
          child.kill("SIGKILL");
          fail(new OpsHavenError("OUTPUT_LIMIT", "Remote command output limit exceeded."));
        } else chunks.push(chunk);
      });
      child.stderr.on("data", () => undefined);
      child.on("error", () => { clearTimeout(timer as any); fail(new OpsHavenError("REMOTE_OPERATION_FAILED", "Remote command could not start.")); });
      child.on("close", (code: number | null) => {
        clearTimeout(timer as any);
        if (settled) return;
        const stdout = Buffer.concat(chunks).toString("utf8");
        if (stdout.includes("\u0000")) return fail(new OpsHavenError("BINARY_OUTPUT", "Binary command output rejected."));
        settled = true;
        resolve({ stdout, exitCode: code ?? 1 });
      });
      child.stdin.on?.("error", () => undefined);
      child.stdin.end(options.stdin ?? "");
    });
  }
}

export async function requireSuccess(runner: CommandRunner, executable: string, args: readonly string[], options: RunOptions): Promise<string> {
  const result = await runner.run(executable, args, options);
  if (result.exitCode !== 0) throw new OpsHavenError("REMOTE_OPERATION_FAILED", "A fixed remote command failed.");
  return result.stdout.trim();
}
