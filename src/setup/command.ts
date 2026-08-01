import { OpsHavenError } from "../errors.js";
import { ensureRemoteSetupState, resolveSetupConfigPath } from "../operator-state.js";
import { endpointStatus, exposeEndpoint } from "./endpoint.js";
import { executeRemoteSetup } from "./engine.js";
import { inspectRemoteSetupRepair, repairRemoteSetup } from "./repair.js";
import { buildRemoteSetupPlan, formatRemoteSetupPlan, loadRemoteSetupConfig } from "./remote.js";
import { rollbackRemoteSetup, uninstallRemoteSetup } from "./rollback.js";
import { prepareRemoteState } from "./state.js";

function value(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}

function required(args: readonly string[], name: string): string {
  const result = value(args, name);
  if (!result) throw new OpsHavenError("CONFIG_INVALID", `Remote setup requires ${name}.`);
  return result;
}

async function setupPath(args: readonly string[], allowGuidedCompletion: boolean): Promise<string> {
  const explicit = value(args, "--config") ?? value(args, "--setup-config");
  if (explicit) return explicit;
  if (allowGuidedCompletion) return await ensureRemoteSetupState(args);
  const configured = await resolveSetupConfigPath(args);
  if (!configured) throw new OpsHavenError("CONFIG_INVALID", "Setup is not initialized.");
  return configured;
}

export async function runRemoteSetup(args: readonly string[]): Promise<void> {
  const config = await loadRemoteSetupConfig(await setupPath(args, true));
  const json = args.includes("--json");
  if (args.includes("--rollback")) {
    const receipt = await rollbackRemoteSetup(config, args.includes("--approve"));
    process.stdout.write(`${JSON.stringify(receipt, null, json ? 0 : 2)}\n`);
    return;
  }
  const inspectionStarted = Date.now();
  let comparison;
  try {
    comparison = await prepareRemoteState(config);
  } catch (error) {
    if (!args.includes("--dry-run")) throw error;
    comparison = undefined;
  }
  const plan = buildRemoteSetupPlan(config, comparison);
  if (args.includes("--dry-run")) {
    process.stdout.write(json ? `${JSON.stringify(plan)}\n` : formatRemoteSetupPlan(plan));
    return;
  }
  if (plan.changeType === "REPAIR_REQUIRED") {
    throw new OpsHavenError("POLICY_DENIED", "Remote state cannot be synchronized safely. Inspect and approve the bounded recovery flow with opshaven setup repair.", false, { safeNextCommand: "opshaven setup repair" });
  }
  const controller = new AbortController();
  process.on("SIGINT", () => controller.abort());
  await executeRemoteSetup(config, plan, {
    nonInteractive: args.includes("--non-interactive"),
    tui: args.includes("--tui"),
    approved: args.includes("--approve"),
    json,
    signal: controller.signal,
    initialTimings: { installedStateInspection: Date.now() - inspectionStarted },
  });
}

function formatRepairPlan(plan: Awaited<ReturnType<typeof inspectRemoteSetupRepair>>): string {
  const lines = [
    "Remote synchronization repair plan",
    "",
    "Action",
    `  ${plan.action}`,
    "",
    "Synchronization transaction",
    `  ${plan.transactionId ?? "none"}`,
    "",
    "Last completed phase",
    `  ${plan.lastCompletedPhase ?? "none"}`,
    "",
    "Previous verified generation",
    `  ${plan.previousGeneration ?? "unavailable"}`,
    "",
    "Rollback material",
    `  ${plan.rollbackAvailable ? "available and integrity-checked" : "unavailable or invalid"}`,
    "",
    "Evidence",
    "  preserved",
    "",
    "Changes",
    ...plan.changes.map((item) => `  ${item}`),
  ];
  return `${lines.join("\n")}\n`;
}

export async function runRemoteRepair(args: readonly string[]): Promise<void> {
  const config = await loadRemoteSetupConfig(await setupPath(args, false));
  const json = args.includes("--json");
  const plan = await inspectRemoteSetupRepair(config);
  if (!args.includes("--approve")) {
    process.stdout.write(json ? `${JSON.stringify(plan)}\n` : formatRepairPlan(plan));
    if (plan.action !== "none") process.exitCode = 2;
    return;
  }
  const receipt = await repairRemoteSetup(config, true);
  if (json) {
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
    return;
  }
  process.stdout.write("✓ Synchronization recovery complete\n\n");
  if (receipt.action === "restore-previous") {
    process.stdout.write("Recovery\n");
    process.stdout.write("  ✓ Previous verified generation restored\n");
    process.stdout.write("  ✓ Dispatcher verified\n");
    process.stdout.write("  ✓ Authorization verified\n");
    process.stdout.write("  ✓ Security boundary verified\n\n");
    process.stdout.write("Current state\n");
    process.stdout.write(`  Generation ${receipt.installedGeneration ?? "unknown"} remains active.\n`);
  } else {
    process.stdout.write("No unresolved synchronization transaction required repair.\n");
  }
}

export async function runRemoteUninstall(args: readonly string[]): Promise<void> {
  const config = await loadRemoteSetupConfig(await setupPath(args, false));
  const receipt = await uninstallRemoteSetup(config, args.includes("--approve"));
  process.stdout.write(`${JSON.stringify(receipt, null, args.includes("--json") ? 0 : 2)}\n`);
}

export async function runEndpointHandoff(args: readonly string[]): Promise<void> {
  const operation = args[0];
  const config = await loadRemoteSetupConfig(await setupPath(args, false));
  if (operation === "status") {
    process.stdout.write(`${JSON.stringify(await endpointStatus(config), null, args.includes("--json") ? 0 : 2)}\n`);
    return;
  }
  if (operation !== "expose") throw new OpsHavenError("CONFIG_INVALID", "Endpoint operation must be expose or status.");
  const receipt = await exposeEndpoint(config, required(args, "--endpoint-config"), required(args, "--external-url"), args.includes("--verify-external"));
  process.stdout.write(`${JSON.stringify(receipt, null, args.includes("--json") ? 0 : 2)}\n`);
}
