#!/usr/bin/env node

import { OpsHavenError } from "./errors.js";
import { formatOperatorError } from "./operator-error-boundary.js";
import { colorEnabled, heading, paint, section } from "./operator-ui.js";

const HELP_COMMANDS = new Set(["help", "--help", "-h"]);
const VERSION_COMMANDS = new Set(["version", "--version", "-V"]);
const KNOWN_COMMANDS = new Set([
  "init", "setup", "uninstall", "endpoint", "doctor", "diagnostics", "boundary", "verify-boundary",
  "app", "deploy", "serve", "validate-config", "verify-audit", "compare-capabilities", "authorization-report",
  "trust-report", "approve-restart", "approve-deploy", "approve-rollback", "print-mcp-config", "print-remote-mcp-url",
]);
const COMMANDS_WITHOUT_LOCAL_CONFIG = new Set(["init", "setup", "uninstall", "endpoint", "doctor", "diagnostics", "compare-capabilities"]);

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}
function explicitConfigPath(): string { return flag("--config") ?? process.env.OPSHAVEN_CONFIG ?? ""; }

function help(): string {
  const color = colorEnabled();
  return `${heading("OpsHaven Operator CLI", color)}
OpsHaven human CLI for secure Linux operations.

${section("Usage", color)}
  opshaven <command> [options]

${section("Start here", color)}
  init                     Configure this operator machine
  app add                  Register a supported application locally
  setup remote             Install or synchronize the remote target
  setup repair             Inspect or repair a failed synchronization
  doctor                   Diagnose canonical local and remote readiness
  boundary verify          Verify the installed deployment boundary

${section("Deploy", color)}
  deploy plan <app>        Choose and plan an immutable revision
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
  --debug                  Show sanitized comparison and timing details

${paint("Recommended deployment onboarding", "info", color)}
  opshaven init
  opshaven app add
  opshaven setup remote
  opshaven doctor
  opshaven boundary verify
  opshaven deploy plan sample-api

Later setup runs compare verified content identities. Unchanged state is verified without mutation. Dispatcher-only and authorization-only changes reuse the installed runtime.

After a failed synchronization:
  opshaven doctor --debug
  opshaven setup repair
  opshaven setup repair --approve

Non-interactive planning must supply:
  opshaven deploy plan sample-api --revision <full-commit-sha>

The opshaven command is for people. MCP clients launch opshaven-mcp.
`;
}

function usageError(message: string): Error { return new Error(message); }

async function main(): Promise<void> {
  const requested = process.argv[2] ?? "help";
  if (HELP_COMMANDS.has(requested)) { process.stdout.write(help()); return; }
  if (VERSION_COMMANDS.has(requested)) { process.stdout.write(`OpsHaven ${process.env.npm_package_version ?? "1.1.0"}\n`); return; }
  if (!KNOWN_COMMANDS.has(requested)) throw usageError(`Unknown command "${requested}".`);
  if (requested === "boundary" && process.argv[3] !== "verify") throw usageError("Unknown boundary command.");

  const commandArgs = process.argv.slice(3);
  if (requested === "init") {
    const { runOnePassFirstRunWizard } = await import("./operator-init-one-pass.js");
    await runOnePassFirstRunWizard(commandArgs);
    return;
  }

  const { resolveLocalConfigPath, resolveSetupConfigPath } = await import("./operator-state.js");
  const explicit = explicitConfigPath();
  const path = explicit || await resolveLocalConfigPath(commandArgs) || "";

  if (requested === "doctor" || requested === "diagnostics") {
    const deployment = await import("./deployment.js");
    const setupPath = await resolveSetupConfigPath(commandArgs);
    if (setupPath) {
      try {
        const [{ loadRemoteSetupConfig }, { runCanonicalHealthDoctor }] = await Promise.all([
          import("./setup/remote.js"),
          import("./operator-health-report.js"),
        ]);
        const handled = await runCanonicalHealthDoctor(await loadRemoteSetupConfig(setupPath), commandArgs);
        if (handled) {
          if (!commandArgs.includes("--json")) await deployment.runDeploymentDoctor(path, commandArgs);
          return;
        }
      } catch {
        // The full doctor below reports connection, configuration, and local-state failures safely.
      }
    }
    const { runDoctor } = await import("./operator-doctor.js");
    await runDoctor(path, commandArgs);
    await deployment.runDeploymentDoctor(path, commandArgs);
    return;
  }

  const requiresLocalConfig = !COMMANDS_WITHOUT_LOCAL_CONFIG.has(requested);
  if (requiresLocalConfig && !path) throw usageError("Setup is not initialized. Operator setup is not initialized.");
  if (requiresLocalConfig && path && !explicit) process.argv.push("--config", path);

  if (requested === "app") {
    const { runAppCommand } = await import("./deployment.js");
    await runAppCommand(path, commandArgs);
    return;
  }
  if (requested === "deploy") {
    const setupPath = await resolveSetupConfigPath(commandArgs);
    if (!setupPath) throw new OpsHavenError("POLICY_DENIED", "Deployment is blocked until remote setup is configured and verified.");
    const [{ loadRemoteSetupConfig }, { inspectInstallationHealth }] = await Promise.all([
      import("./setup/remote.js"),
      import("./setup/health.js"),
    ]);
    const setup = await loadRemoteSetupConfig(setupPath);
    const health = await inspectInstallationHealth(setup);
    if (!health.deploymentAllowed) {
      throw new OpsHavenError(
        "POLICY_DENIED",
        health.repairRequired
          ? "Deployment is blocked because the remote installation requires reviewed repair."
          : "Deployment is blocked because the canonical remote state requires synchronization.",
        false,
        {
          currentKnownState: health.primary,
          healthStates: health.states,
          repairClassification: health.repairClassification,
          reasons: health.reasons,
          blockedOperations: ["deployment planning", "deployment apply"],
          safeNextCommand: health.safeNextCommand ?? "opshaven setup remote",
        },
      );
    }
    const { runDeployCommand } = await import("./deployment.js");
    await runDeployCommand(path, commandArgs);
    return;
  }

  if (requested === "boundary" || requested === "verify-boundary") {
    const setupPath = await resolveSetupConfigPath(commandArgs);
    if (setupPath) {
      if (!flag("--setup-config") && !explicit) process.argv.push("--setup-config", setupPath);
      const [{ loadRemoteSetupConfig }, { inspectInstallationHealth }] = await Promise.all([
        import("./setup/remote.js"),
        import("./setup/health.js"),
      ]);
      const setup = await loadRemoteSetupConfig(setupPath);
      const health = await inspectInstallationHealth(setup);
      if (!health.boundaryCertificationAllowed) {
        throw new OpsHavenError(
          "POLICY_DENIED",
          "Boundary certification is blocked because the installed generation cannot be verified completely.",
          false,
          {
            currentKnownState: health.primary,
            healthStates: health.states,
            repairClassification: health.repairClassification,
            reasons: health.reasons,
            verifiedProtections: ["pinned host identity remains required", "arbitrary commands remain denied"],
            safeNextCommand: health.safeNextCommand ?? "opshaven setup remote",
          },
        );
      }
    }
  }
  if (requested === "authorization-report") process.argv[2] = "trust-report";
  await import("./cli.js");
}

main().catch((error: unknown) => {
  process.stderr.write(`${formatOperatorError(error)}\n`);
  process.exitCode = 1;
});
