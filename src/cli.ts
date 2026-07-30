#!/usr/bin/env node
import { loadConfig } from "./config/load.js";
import { verifyAuditLog } from "./security/audit.js";

function usage(): never {
  process.stderr.write("Usage: opshaven audit verify --config /absolute/path/config.json\n");
  process.exit(2);
}

async function main(): Promise<void> {
  const [command, subcommand, flag, configPath, ...rest] = process.argv.slice(2);
  if (command !== "audit" || subcommand !== "verify" || flag !== "--config" || configPath === undefined || rest.length > 0) {
    usage();
  }
  const config = await loadConfig(configPath);
  const result = await verifyAuditLog(config.audit.path);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.valid) process.exitCode = 1;
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "Command failed"}\n`);
  process.exitCode = 1;
});
