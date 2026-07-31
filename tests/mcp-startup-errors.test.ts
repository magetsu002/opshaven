import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import test from "node:test";

interface Result { code: number | null; stdout: string; stderr: string }

async function runMcp(args: string[], env: Record<string, string | undefined>): Promise<Result> {
  const child = spawn(process.execPath, [path.join(process.cwd(), "dist/src/index.js"), ...args], {
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", ...env },
  });
  return await new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("MCP startup error process timed out."));
    }, 5000);
    child.stdout.on("data", (chunk: Uint8Array) => { stdout += Buffer.from(chunk).toString("utf8"); });
    child.stderr.on("data", (chunk: Uint8Array) => { stderr += Buffer.from(chunk).toString("utf8"); });
    child.on("error", (error: unknown) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code: number | null) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

test("MCP startup explains a missing configuration path", async () => {
  const result = await runMcp([], { HOME: "/home/operator" });
  assert.equal(result.code, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /^Startup blocked\./);
  assert.match(result.stderr, /Reason:\nMissing local configuration path\./);
  assert.match(result.stderr, /Checked:\n--config\nOPSHAVEN_CONFIG/);
  assert.match(result.stderr, /opshaven-mcp --config <path>/);
  assert.doesNotMatch(result.stderr, /failed to start safely/i);
});

test("MCP startup reports the failed validation without exposing a full home path", async () => {
  const home = "/home/operator";
  const config = `${home}/.config/opshaven/config.json`;
  const result = await runMcp(["--config", config], { HOME: home });
  assert.equal(result.code, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /Reason:\nlocal configuration must be a safe regular non-symlink file\./i);
  assert.match(result.stderr, /Checked:\n~\/\.config\/opshaven\/config\.json/);
  assert.match(result.stderr, /opshaven doctor --config ~\/\.config\/opshaven\/config\.json/);
  assert.doesNotMatch(result.stderr, /\/home\/operator/);
  assert.doesNotMatch(result.stderr, /PRIVATE KEY|BEGIN [A-Z ]+ KEY/);
});
