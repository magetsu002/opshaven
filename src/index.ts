#!/usr/bin/env node
import { createInterface } from "node:readline";
import { AgentToolExecutor } from "./agent-executor.js";
import { ContinuityToolExecutor } from "./continuity.js";
import { DeploymentPlanner } from "./deployment/planning.js";
import { loadConfig } from "./config.js";
import { McpServer } from "./mcp.js";
import { OperationService } from "./operations.js";
import { resolveLocalConfigPath } from "./operator-state.js";
import { WorkspaceToolExecutor } from "./workspace-tools.js";

function explicitConfigPath(): string {
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
  const explicit = explicitConfigPath();
  if (explicit) {
    const checked = displayPath(explicit);
    return `Startup blocked.\n\nReason:\n${safeReason(error)}\n\nChecked remote configuration:\n${checked}\n\nAction:\nRun:\nopshaven doctor --config ${checked}\n`;
  }
  return `Startup blocked.\n\nReason:\n${safeReason(error)}\n\nAction:\nRun:\nopshaven workspace list\n`;
}

async function main(): Promise<void> {
  const explicit = explicitConfigPath();
  const configPath = explicit || await resolveLocalConfigPath(process.argv.slice(2)) || "";
  let remote: OperationService | undefined;
  let planner: DeploymentPlanner | undefined;
  if (configPath) {
    const config = await loadConfig(configPath);
    remote = new OperationService(config, undefined, configPath);
    planner = new DeploymentPlanner(config, configPath, { client: remote });
  }
  const workspace = new WorkspaceToolExecutor();
  const continuity = new ContinuityToolExecutor(workspace, planner);
  const server = new McpServer(new AgentToolExecutor(workspace, remote, continuity));
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
