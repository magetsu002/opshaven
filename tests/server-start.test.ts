import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

async function root(): Promise<string> {
  return await fs.mkdtemp(path.join(tmpdir(), "opshaven-startup-"));
}

test("compiled stdio MCP server starts from a real configuration", async () => {
  const directory = await root();
  const configPath = path.join(directory, "config.json");
  await fs.writeFile(configPath, JSON.stringify({
    version: 1,
    policyVersion: "v1",
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    audit: { path: path.join(directory, "audit.jsonl") },
    approvals: {
      directory: path.join(directory, "approvals"),
      secretFile: path.join(directory, "approval.key"),
      signingPrivateKeyFile: path.join(directory, "private.pem"),
      verificationPublicKeyFile: path.join(directory, "public.pem"),
      remoteUsedDirectory: path.join(directory, "remote-used"),
      defaultTtlSeconds: 300,
    },
    secretFingerprints: [],
    resources: [{
      id: "host.fixture",
      kind: "host",
      address: "fixture.internal",
      port: 22,
      user: "opshaven",
      knownHostsFile: "/etc/opshaven/known_hosts",
      identityFile: "/etc/opshaven/id_ed25519",
      connectTimeoutMs: 5000,
    }],
  }), { mode: 0o600 });

  const child = spawn(process.execPath, [path.join(process.cwd(), "dist/src/index.js"), "--config", configPath], {
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
  });

  const output = await new Promise<string>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("MCP startup process timed out."));
    }, 5000);
    child.stdout.on("data", (chunk: Uint8Array) => { stdout += Buffer.from(chunk).toString("utf8"); });
    child.stderr.on("data", (chunk: Uint8Array) => { stderr += Buffer.from(chunk).toString("utf8"); });
    child.on("error", (error: unknown) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code: number | null) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`MCP startup failed safely: ${stderr}`));
      else resolve(stdout);
    });
    child.stdin.end(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`);
  });

  const response = JSON.parse(output.trim()) as Record<string, unknown>;
  assert.equal(response.jsonrpc, "2.0");
  assert.equal(response.id, 1);
  const result = response.result as Record<string, unknown>;
  const serverInfo = result.serverInfo as Record<string, unknown>;
  assert.equal(serverInfo.name, "opshaven");
});
