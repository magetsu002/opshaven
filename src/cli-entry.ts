#!/usr/bin/env node

import { formatOperatorError } from "./operator-errors.js";
import { colorEnabled, heading, paint, section } from "./operator-ui.js";

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
  "app",
  "deploy",
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
  const color = colorEnabled();
  return `${heading("OpsHaven Operator CLI", color)}
OpsHaven human CLI for secure Linux operations.

${section("Usage", color)}
  opshaven <command> [options]

${section("Start here", color)}
  init                     Configure this operator machine
  setup remote             Install and verify the remote runtime
  doctor                   Diagnose local and remote readiness
  boundary verify          Verify the installed security boundary

${section("Deploy", color)}
  app add                  Register one supported application
  deploy plan <app>        Create an immutable exact-revision plan
  deploy apply <plan-id>   Apply only the stored approved plan

${section("Operate", color)}
  authorization-report     Explain the current authorization state
  endpoint expose|status   Manage reviewed endpoint handoff
  uninstall remote         Remove the recorded remote installation

${section("Advanced", color)}
  validate-config          Validate generated operator configuration
  verify-audit             Verify the tamper-evident audit chain
  compare-capabilities     Compare build authorization declarations
  print-mcp-config         Print MCP client configuration
  print-remote-mcp-url     Print the configured remote MCP URL
  approve-restart          Create a one-time restart approval
  approve-deploy           Create a one-time deployment approval
  approve-rollback         Create a one-time rollback approval
  serve                    Start the explicitly configured HTTP transport

${section("Global options", color)}
  --help, -h               Show this help
  --version, -V            Show the CLI version
  --json                   Produce machine-readable output where supported
  --debug                  Show lower-level diagnostic details

${paint("Normal operator workflow", "info", color)}
  opshaven init
  opshaven setup remote
  opshaven app add
  opshaven deploy plan sample-api --revision <full-commit-sha>
  opshaven deploy apply <plan-id>
  opshaven doctor
  opshaven boundary verify

The opshaven command is for people. MCP clients launch opshaven-mcp.
`;
}

function usageError(message: string): Error {
  return new Error(message);
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
    throw usageError(`Unknown command "${requested}".`);
  }
  if (requested === "boundary" && process.argv[3] !== "verify") {
    throw usageError("Unknown boundary command.");
  }

  const commandArgs = process.argv.slice(3);
  if (requested === "init") {
    const { runFirstRunWizard } = await import("./operator-init.js");
    await runFirstRunWizard(commandArgs);
    return;
  }

  const { resolveLocalConfigPath, resolveSetupConfigPath } = await import("./operator-state.js");
  const explicit = explicitConfigPath();
  const path = explicit || await resolveLocalConfigPath(commandArgs) || "";

  if (requested === "doctor" || requested === "diagnostics") {
    const { runDoctor } = await import("./operator-doctor.js");
    await runDoctor(path, commandArgs);
    const { runDeploymentDoctor } = await import("./deployment.js");
    await runDeploymentDoctor(path, commandArgs);
    return;
  }

  const requiresLocalConfig = !COMMANDS_WITHOUT_LOCAL_CONFIG.has(requested);
  if (requiresLocalConfig && !path) {
    throw usageError("Setup is not initialized. Operator setup is not initialized.");
  }
  if (requiresLocalConfig && path && !explicit) process.argv.push("--config", path);

  if (requested === "app") {
    const { runAppCommand } = await import("./deployment.js");
    await runAppCommand(path, commandArgs);
    return;
  }
  if (requested === "deploy") {
    const { runDeployCommand } = await import("./deployment.js");
    await runDeployCommand(path, commandArgs);
    return;
  }

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
