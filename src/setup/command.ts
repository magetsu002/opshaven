import { OpsHavenError } from "../errors.js";
import { ensureRemoteSetupState, resolveSetupConfigPath } from "../operator-state.js";
import { endpointStatus, exposeEndpoint } from "./endpoint.js";
import { executeRemoteSetup } from "./engine.js";
import { createSetupPresenter, type SetupPresenter } from "./presentation.js";
import { inspectRemoteSetupRepair, prepareReviewedCleanReinstall, repairRemoteSetup } from "./repair.js";
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

function suppressReceipt(base: SetupPresenter): SetupPresenter {
  const presenter: SetupPresenter = {
    plan: (value) => base.plan(value),
    step: (id, scope, state, detail) => base.step(id, scope, state, detail),
    fingerprint: (label, value) => base.fingerprint(label, value),
    approve: async (message) => await base.approve(message),
    receipt: () => undefined,
  };
  if (base.progress) presenter.progress = (id, detail, elapsedMs) => base.progress?.(id, detail, elapsedMs);
  if (base.heartbeatMs) presenter.heartbeatMs = () => base.heartbeatMs?.() ?? 15000;
  if (base.cancellation) presenter.cancellation = (mutationStarted, restored) => base.cancellation?.(mutationStarted, restored);
  return presenter;
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

  if (args.includes("--clean-reinstall")) {
    const evidence = await prepareReviewedCleanReinstall(config, true);
    const comparison = await prepareRemoteState(config);
    const setupPlan = buildRemoteSetupPlan(config, comparison);
    if (setupPlan.changeType !== "FULL_INSTALL") throw new OpsHavenError("POLICY_DENIED", "Reviewed clean reinstall preparation did not produce an empty installation state.", false, { evidenceRoot: evidence.evidenceRoot });
    const controller = new AbortController();
    process.on("SIGINT", () => controller.abort());
    const basePresenter = createSetupPresenter({ tui: args.includes("--tui"), nonInteractive: true, preapproved: true, json });
    const setup = await executeRemoteSetup(config, setupPlan, {
      nonInteractive: true,
      tui: args.includes("--tui"),
      approved: true,
      json,
      signal: controller.signal,
      presenter: suppressReceipt(basePresenter),
    });
    const combined = Object.freeze({ ok: true, action: "clean-reinstall", evidence, setup });
    if (json) {
      process.stdout.write(`${JSON.stringify(combined)}\n`);
      return;
    }
    process.stdout.write("✓ Reviewed clean reinstall complete\n\n");
    process.stdout.write("Evidence\n");
    process.stdout.write(`  Preserved under ${evidence.evidenceRoot}\n`);
    process.stdout.write(`  Manifest ${evidence.evidenceManifestSha256}\n\n`);
    process.stdout.write("Current state\n");
    process.stdout.write("  ✓ New reviewed generation installed\n");
    process.stdout.write("  ✓ Dispatcher and authorization verified\n");
    process.stdout.write("  ✓ Canonical readiness and security boundary verified\n");
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
