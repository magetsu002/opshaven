#!/usr/bin/env node
import { createInterface } from "node:readline";
import { loadConfig } from "./config.js";
import { McpServer } from "./mcp.js";
import { OperationService } from "./operations.js";

function configuredPath(): string {
  const index = process.argv.indexOf("--config");
  return (index >= 0 ? process.argv[index + 1] : process.env.OPSHAVEN_CONFIG) ?? "";
}

function displayPath(value: string): string {
  const home = process.env.HOME;
  if (home && (value === home || value.startsWith(`${home}/`))) return `~${value.slice(home.length)}`;
  return value.startsWith("/") ? "<configured path>" : value;
}

function safeReason(error: unknown): string {
  const raw = error instanceof Error ? error.message : "MCP server startup validation failed.";
  const withoutPaths = raw.replace(/\/[A-Za-z0-9._/-]+/g, "<protected path>");
  return /^[A-Za-z0-9 .,:;()'"_<>-]{1,240}$/.test(withoutPaths)
    ? withoutPaths
    : "MCP server startup validation failed.";
}

function startupMessage(error: unknown): string {
  const path = configuredPath();
  if (!path) {
    return `Startup blocked.\n\nReason:\nMissing local configuration path.\n\nChecked:\n--config\nOPSHAVEN_CONFIG\n\nAction:\nRun:\nopshaven-mcp --config <path>\n`;
  }
  const checked = displayPath(path);
  return `Startup blocked.\n\nReason:\n${safeReason(error)}\n\nChecked:\n${checked}\n\nAction:\nRun:\nopshaven doctor --config ${checked}\n`;
}

async function main(): Promise<void> {
  const path = configuredPath();
  if (!path) throw new Error("Missing local configuration path.");
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

main().catch((error: unknown) => {
  process.stderr.write(startupMessage(error));
  process.exitCode = 1;
});
