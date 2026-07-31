#!/usr/bin/env node

const HELP_COMMANDS = new Set(["help", "--help", "-h"]);
const VERSION_COMMANDS = new Set(["version", "--version", "-V"]);
const KNOWN_COMMANDS = new Set([
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
const COMMANDS_WITHOUT_LOCAL_CONFIG = new Set(["setup", "uninstall", "endpoint", "compare-capabilities"]);

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function configPath(): string {
  return flag("--config") ?? process.env.OPSHAVEN_CONFIG ?? "";
}

function help(): string {
  return `OpsHaven human CLI

Usage:
  opshaven <command> [options]

Operator workflow:
  setup remote             Install the reviewed read-only runtime
  uninstall remote         Remove the recorded remote installation
  doctor                   Diagnose operator and deployment readiness
  boundary verify          Run boundary verification
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
    throw startupBlocked("Unknown boundary command.", "Run:\nopshaven boundary verify --config <path>");
  }
  const path = configPath();
  if (!COMMANDS_WITHOUT_LOCAL_CONFIG.has(requested) && !path) {
    throw startupBlocked(`Configuration required for "${requested}".`, "Run:\nopshaven doctor --config <path>");
  }
  if (requested === "doctor" || requested === "diagnostics") {
    const { runDoctor } = await import("./operator-doctor.js");
    await runDoctor(path, process.argv.slice(3));
    return;
  }
  if (requested === "authorization-report") process.argv[2] = "trust-report";
  await import("./cli.js");
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "Command failed safely."}\n`);
  process.exitCode = 1;
});
