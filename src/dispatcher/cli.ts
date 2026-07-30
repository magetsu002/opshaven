#!/usr/bin/env node
import { loadConfig } from "../config/load.js";
import { OpsHavenError } from "../core/errors.js";
import { Dispatcher } from "./dispatcher.js";
import { DISPATCHER_HANDLERS } from "./handlers.js";
import { readSingleJsonLine } from "./io.js";

async function main(): Promise<void> {
  if (process.argv.length !== 2) throw new OpsHavenError("POLICY_DENIED", "Dispatcher accepts no command-line arguments");
  const originalCommand = process.env["SSH_ORIGINAL_COMMAND"];
  if (originalCommand !== undefined && originalCommand !== "opshaven-dispatch") {
    throw new OpsHavenError("POLICY_DENIED", "SSH original command is not allowlisted");
  }
  const configPath = process.env["OPSHAVEN_DISPATCH_CONFIG"] ?? "/etc/opshaven/dispatcher.json";
  if (!configPath.startsWith("/")) throw new OpsHavenError("CONFIG_INVALID", "Dispatcher config path must be absolute");
  const config = await loadConfig(configPath);
  const hostId = process.env["OPSHAVEN_HOST_ID"];
  if (hostId === undefined) throw new OpsHavenError("CONFIG_INVALID", "OPSHAVEN_HOST_ID is required");
  const dispatcher = new Dispatcher(config, DISPATCHER_HANDLERS, hostId);
  const request = await readSingleJsonLine(process.stdin);
  process.stdout.write(`${JSON.stringify(await dispatcher.handle(request))}\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Dispatcher startup failed";
  process.stdout.write(`${JSON.stringify({
    version: 1,
    requestId: "00000000-0000-4000-8000-000000000000",
    ok: false,
    error: { code: "OPERATION_FAILED", message, retryable: false, details: {} }
  })}\n`);
  process.exitCode = 1;
});
