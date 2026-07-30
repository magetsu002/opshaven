#!/usr/bin/env node
import { loadConfig } from "./config/load.js";
import { McpStdioServer } from "./mcp/server.js";
import { OperationsService } from "./service/operations-service.js";
import { VERSION } from "./version.js";

export function startupBanner(): string {
  return `OpsHaven MCP ${VERSION}`;
}

function configPath(args: readonly string[]): string | undefined {
  if (args.length === 2 && args[0] === "--config" && args[1]?.startsWith("/")) return args[1];
  if (args.length === 0 && process.env.OPSHAVEN_CONFIG?.startsWith("/")) return process.env.OPSHAVEN_CONFIG;
  return undefined;
}

export async function main(args: readonly string[] = process.argv.slice(2)): Promise<void> {
  const path = configPath(args);
  if (path === undefined) {
    throw new Error("Usage: opshaven-mcp --config /absolute/path/opshaven.config.json");
  }
  const config = await loadConfig(path);
  process.stderr.write(`${startupBanner()}\n`);
  await new McpStdioServer(new OperationsService(config), process.stdin, process.stdout).run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : "OpsHaven MCP failed"}\n`);
    process.exitCode = 1;
  });
}
