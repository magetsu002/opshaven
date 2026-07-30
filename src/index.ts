#!/usr/bin/env node
import { createInterface } from "node:readline";
import { loadConfig } from "./config.js";
import { McpServer } from "./mcp.js";
import { OperationService } from "./operations.js";

function configPath(): string {
  const index = process.argv.indexOf("--config");
  const configured = index >= 0 ? process.argv[index + 1] : process.env.OPSHAVEN_CONFIG;
  if (!configured) throw new Error("A local configuration path is required through --config or OPSHAVEN_CONFIG.");
  return configured;
}

async function main(): Promise<void> {
  const path = configPath();
  const config = await loadConfig(path);
  const server = new McpServer(new OperationService(config, undefined, path));
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
  for await (const line of lines) {
    if (typeof line !== "string" || line.trim().length === 0) continue;
    let response: Record<string, unknown> | null;
    try { response = await server.handle(JSON.parse(line) as unknown); }
    catch { response = { jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } }; }
    if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
  }
}

main().catch(() => {
  process.stderr.write("OpsHaven failed to start safely. Validate the local configuration and protected key files.\n");
  process.exitCode = 1;
});
