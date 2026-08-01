import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import test from "node:test";

interface Result { code: number | null; stdout: string; stderr: string }

async function runCli(args: string[], env: Record<string, string | undefined> = {}): Promise<Result> {
  const child = spawn(process.execPath, [path.join(process.cwd(), "dist/src/cli-entry.js"), ...args], {
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", ...env },
  });
  return await new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("CLI process timed out."));
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

for (const command of [["help"], ["--help"], ["-h"]]) {
  test(`CLI ${command[0]} works without configuration`, async () => {
    const result = await runCli(command, { NO_COLOR: "" });
    assert.equal(result.code, 0);
    assert.match(result.stdout, /OpsHaven Operator CLI/);
    assert.match(result.stdout, /OpsHaven human CLI/);
    assert.match(result.stdout, /opshaven init/);
    assert.match(result.stdout, /opshaven setup remote/);
    assert.match(result.stdout, /opshaven doctor/);
    assert.match(result.stdout, /opshaven boundary verify/);
    assert.match(result.stdout, /opshaven-mcp/);
    assert.doesNotMatch(result.stdout, /node dist\/src\/cli-entry\.js/);
    assert.doesNotMatch(result.stdout, /\u001b\[/);
    assert.equal(result.stderr, "");
  });
}

test("CLI version works without configuration", async () => {
  const result = await runCli(["--version"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /^OpsHaven \d+\.\d+\.\d+\n$/);
  assert.equal(result.stderr, "");
});

test("invalid CLI commands answer what happened and what to run next", async () => {
  const result = await runCli(["not-a-command"], { NO_COLOR: "" });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Startup blocked\./);
  assert.match(result.stderr, /✗ Command not recognized/);
  assert.match(result.stderr, /Cause:\nUnknown command "not-a-command"\./);
  assert.match(result.stderr, /Next:/);
  assert.match(result.stderr, /Run:\n  opshaven help/);
  assert.doesNotMatch(result.stderr, /configuration path is required/i);
  assert.doesNotMatch(result.stderr, /\u001b\[/);
});

test("operational CLI commands clearly route an uninitialized operator", async () => {
  const result = await runCli(["validate-config"], { NO_COLOR: "" });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /OpsHaven is not initialized/);
  assert.match(result.stderr, /Setup is not initialized\./);
  assert.match(result.stderr, /Checked:\n✗ Local operator setup/);
  assert.match(result.stderr, /Run:\n  opshaven init/);
  assert.doesNotMatch(result.stderr, /RemoteSetupConfig|schema/i);
});
