#!/usr/bin/env node

import { OpsHavenError } from "./errors.js";
import { formatOperatorError } from "./operator-error-boundary.js";
import { colorEnabled, heading, paint, section } from "./operator-ui.js";
import { getPackageVersion } from "./version.js";

const HELP_COMMANDS = new Set(["help", "--help", "-h"]);
const VERSION_COMMANDS = new Set(["version", "--version", "-V"]);
const KNOWN_COMMANDS = new Set([
  "init", "workspace", "permissions", "connect", "setup", "uninstall", "endpoint", "doctor", "diagnostics", "boundary", "verify-boundary",
  "app", "deploy", "serve", "validate-config", "verify-audit", "compare-capabilities", "authorization-report",
  "trust-report", "approve-restart", "approve-deploy", "approve-rollback", "print-mcp-config", "print-remote-mcp-url",
]);
const COMMANDS_WITHOUT_LOCAL_CONFIG = new Set(["init", "workspace", "permissions", "connect", "setup", "uninstall", "endpoint", "doctor", "diagnostics", "compare-capabilities"]);
const REMOTE_INIT_FLAGS = ["--host", "--host-key-sha256", "--admin-user", "--admin-identity", "--known-hosts", "--privilege", "--source-sha"];

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}
function explicitConfigPath(): string { return flag("--config") ?? process.env.OPSHAVEN_CONFIG ?? ""; }

function help(): string {
  const color = colorEnabled();
  return `${heading("OpsHaven Operator CLI", color)}
OpsHaven human CLI for context-rich local engineering workspaces, with mature remote operations available when needed.

${section("Usage", color)}
  opshaven <command> [options]

${section("Start", color)}
  init                              Initialize local OpsHaven state
  workspace add <directory>         Register a local project
  workspace list                    List local projects and permissions
  connect                           Show MCP connection instructions

${section("Work", color)}
  workspace info <id>               Show project metadata and status
  workspace permissions <id>        View or change AI permissions
  permissions <id>                  Short alias for workspace permissions

${section("Remote / Server", color)}
  app add                           Register a deployment application
  setup remote                      Install or synchronize a remote target
  setup repair                      Inspect or repair failed synchronization
  doctor                            Diagnose local and remote readiness
  boundary verify                   Verify the installed deployment boundary
  deploy plan <app>                 Plan an immutable deployment revision
  deploy apply <plan-id>            Apply only the stored deployment plan
  endpoint expose|status            Manage reviewed remote endpoint handoff
  uninstall remote                  Remove the recorded remote installation

${section("Advanced", color)}
  diagnostics                       Show deeper diagnostic state
  validate-config                   Validate generated remote configuration
  verify-audit                      Verify the tamper-evident audit chain
  compare-capabilities              Compare build authorization declarations
  authorization-report              Explain remote authorization state
  print-mcp-config                  Print legacy MCP client configuration
  print-remote-mcp-url              Print the configured remote MCP URL
  approve-restart                   Create a one-time remote restart approval
  approve-deploy                    Create a one-time remote deployment approval
  approve-rollback                  Create a one-time remote rollback approval
  serve                             Start the explicitly configured HTTP transport

${section("Global options", color)}
  --help, -h                        Show this help
  --version, -V                     Show the CLI version
  --json                            Produce machine-readable output where supported
  --debug                           Show sanitized comparison and timing details

${paint("Local agent workflow", "info", color)}
  opshaven init
  opshaven workspace add ~/Projects/example
  opshaven connect

Workspace onboarding keeps the permission model intentionally small: read project, edit project, run project tasks, and run broader commands. Editing never silently enables command execution.

Remote setup remains available with:
  opshaven setup remote
  opshaven doctor
  opshaven boundary verify

The opshaven command is the OpsHaven human CLI. MCP clients launch opshaven-mcp.
`;
}

function usageError(message: string): Error { return new Error(message); }

async function main(): Promise<void> {
  const requested = process.argv[2] ?? "help";
  if (HELP_COMMANDS.has(requested)) { process.stdout.write(help()); return; }
  if (VERSION_COMMANDS.has(requested)) { process.stdout.write(`OpsHaven ${await getPackageVersion()}\n`); return; }
  if (!KNOWN_COMMANDS.has(requested)) throw usageError(`Unknown command "${requested}".`);
  if (requested === "boundary" && process.argv[3] !== "verify") throw usageError("Unknown boundary command.");

  const commandArgs = process.argv.slice(3);
  if (requested === "init") {
    const { runOnePassFirstRunWizard } = await import("./operator-init-one-pass.js");
    const wantsRemoteInit = REMOTE_INIT_FLAGS.some((name) => commandArgs.includes(name));
    const initArgs = commandArgs.includes("--local-only") || wantsRemoteInit ? commandArgs : [...commandArgs, "--local-only"];
    await runOnePassFirstRunWizard(initArgs);
    return;
  }
  if (requested === "workspace") {
    const { runWorkspaceCommand } = await import("./workspace-cli.js");
    await runWorkspaceCommand(commandArgs);
    return;
  }
  if (requested === "permissions") {
    const { runPermissionsCommand } = await import("./workspace-cli.js");
    await runPermissionsCommand(commandArgs);
    return;
  }
  if (requested === "connect") {
    const { runConnectCommand } = await import("./workspace-cli.js");
    runConnectCommand(commandArgs);
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
  if (requiresLocalConfig && !path) throw new OpsHavenError("CONFIG_INVALID", "Setup is not initialized.");
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
