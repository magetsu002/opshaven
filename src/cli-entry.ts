#!/usr/bin/env node

import { formatOperatorError } from "./operator-errors.js";

const HELP_COMMANDS = new Set(["help", "--help", "-h"]);
const VERSION_COMMANDS = new Set(["version", "--version", "-V"]);
const KNOWN_COMMANDS = new Set([
  "init",
  "setup",
  "uninstall",
  "endpoint",
  "doctor",
  "diagnostics",
  "boundary",
  "verify-boundary",
  "serve",
  "validate-config",
  "verify-audit",
  "compare-capabilities",
  "authorization-report",
  "trust-report",
  "approve-restart",
  "approve-deploy",
  "approve-rollback",
  "print-mcp-config",
  "print-remote-mcp-url",
]);
const COMMANDS_WITHOUT_LOCAL_CONFIG = new Set(["init", "setup", "uninstall", "endpoint", "doctor", "diagnostics", "compare-capabilities"]);

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function explicitConfigPath(): string {
  return flag("--config") ?? process.env.OPSHAVEN_CONFIG ?? "";
}

function help(): string {
  return `OpsHaven human CLI

Usage:
  opshaven <command> [options]

First run:
  init                     Prepare local operator state and authorization keys
  setup remote             Install the reviewed read-only runtime
  doctor                   Show current state, blockers, and the next action
  boundary verify          Verify the installed boundary

Operator workflow:
  uninstall remote         Remove the recorded remote installation
  endpoint expose|status   Manage reviewed endpoint handoff
  authorization-report     Explain active capability authorization

Configuration and audit:
  validate-config          Validate local policy and authorization artifacts
  verify-audit             Verify the tamper-evident audit chain
  compare-capabilities     Compare build capability declarations
  print-mcp-config         Print local MCP client configuration
  print-remote-mcp-url     Print the configured remote MCP URL

Controlled local approvals:
  approve-restart
  approve-deploy
  approve-rollback

Remote transport:
  serve                    Start the explicitly configured HTTP transport

Other:
  help, --help, -h         Show this help
  version, --version, -V   Show the CLI version

Normal first run:
  opshaven init
  opshaven setup remote
  opshaven doctor
  opshaven boundary verify

Existing installations may continue passing --config and --setup-config explicitly.

MCP protocol server:
  opshaven-mcp --config <path>

The opshaven command is for humans. The opshaven-mcp executable is for MCP clients.
`;
}

function startupBlocked(reason: string, action: string): Error {
  return new Error(`Startup blocked.\n\nReason:\n${reason}\n\nAction:\n${action}`);
}

async function main(): Promise<void> {
  const requested = process.argv[2] ?? "help";
  if (HELP_COMMANDS.has(requested)) {
    process.stdout.write(help());
    return;
  }
  if (VERSION_COMMANDS.has(requested)) {
    process.stdout.write(`OpsHaven ${process.env.npm_package_version ?? "1.0.0"}\n`);
    return;
  }
  if (!KNOWN_COMMANDS.has(requested)) {
    throw startupBlocked(`Unknown command "${requested}".`, "Run:\nopshaven help");
  }
  if (requested === "boundary" && process.argv[3] !== "verify") {
    throw startupBlocked("Unknown boundary command.", "Run:\nopshaven boundary verify");
  }

  const commandArgs = process.argv.slice(3);
  if (requested === "init") {
    const { runInit } = await import("./operator-state.js");
    await runInit(commandArgs);
    return;
  }

  const { resolveLocalConfigPath, resolveSetupConfigPath } = await import("./operator-state.js");
  const explicit = explicitConfigPath();
  const path = explicit || await resolveLocalConfigPath(commandArgs) || "";

  if ((requested === "doctor" || requested === "diagnostics")) {
    const { runDoctor } = await import("./operator-doctor.js");
    await runDoctor(path, commandArgs);
    return;
  }

  if (!COMMANDS_WITHOUT_LOCAL_CONFIG.has(requested) && !path) {
    throw startupBlocked("Operator setup is not initialized.", "Run:\nopshaven init");
  }
  if (path && !explicit) process.argv.push("--config", path);

  if ((requested === "boundary" || requested === "verify-boundary") && !flag("--setup-config") && !explicit) {
    const setupPath = await resolveSetupConfigPath(commandArgs);
    if (setupPath) process.argv.push("--setup-config", setupPath);
  }

  if (requested === "authorization-report") process.argv[2] = "trust-report";
  await import("./cli.js");
}

main().catch((error: unknown) => {
  process.stderr.write(`${formatOperatorError(error)}\n`);
  process.exitCode = 1;
});
