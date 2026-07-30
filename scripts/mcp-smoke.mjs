import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const work = await mkdtemp(join(tmpdir(), "opshaven-smoke-"));
try {
  const config = JSON.parse(await readFile(resolve("examples/opshaven.config.json"), "utf8"));
  config.audit.path = join(work, "audit.jsonl");
  config.approvals.stateDirectory = join(work, "approvals");
  const configPath = join(work, "config.json");
  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });

  const child = spawn(process.execPath, [resolve("dist/index.js"), "--config", configPath], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, OPSHAVEN_APPROVAL_KEY: "smoke-test-key-material-not-a-production-secret" }
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "server/discover" })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })}\n`);
  child.stdin.end();

  const exitCode = await new Promise((resolveExit, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("MCP smoke test timed out"));
    }, 5000);
    child.once("error", reject);
    child.once("close", (code) => {
      clearTimeout(timer);
      resolveExit(code);
    });
  });
  if (exitCode !== 0) throw new Error(`MCP server exited with ${exitCode}: ${Buffer.concat(stderr).toString("utf8")}`);
  const lines = Buffer.concat(stdout).toString("utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  if (lines.length !== 2 || lines[0]?.id !== 1 || lines[1]?.id !== 2) throw new Error("Unexpected MCP response sequence");
  if (lines[0]?.result?.serverInfo?.name !== "opshaven") throw new Error("Discovery response is invalid");
  const tools = lines[1]?.result?.tools;
  if (!Array.isArray(tools) || tools.length !== 15) throw new Error("Tool catalogue is incomplete");
  if (!Buffer.concat(stderr).toString("utf8").includes("OpsHaven MCP")) throw new Error("Startup banner was not emitted");
  process.stdout.write("MCP stdio process smoke test passed with 15 tools.\n");
} finally {
  await rm(work, { recursive: true, force: true });
}
