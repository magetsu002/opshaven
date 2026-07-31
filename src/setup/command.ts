import { OpsHavenError } from "../errors.js";
import { ensureRemoteSetupState, resolveSetupConfigPath } from "../operator-state.js";
import { endpointStatus, exposeEndpoint } from "./endpoint.js";
import { executeRemoteSetup } from "./engine.js";
import { buildRemoteSetupPlan, formatRemoteSetupPlan, loadRemoteSetupConfig } from "./remote.js";
import { rollbackRemoteSetup, uninstallRemoteSetup } from "./rollback.js";

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
  const plan = buildRemoteSetupPlan(config);
  if (args.includes("--dry-run")) {
    process.stdout.write(json ? `${JSON.stringify(plan)}\n` : formatRemoteSetupPlan(plan));
    return;
  }
  await executeRemoteSetup(config, plan, {
    nonInteractive: args.includes("--non-interactive"),
    tui: args.includes("--tui"),
    approved: args.includes("--approve"),
    json,
  });
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
  const receipt = await exposeEndpoint(
    config,
    required(args, "--endpoint-config"),
    required(args, "--external-url"),
    args.includes("--verify-external"),
  );
  process.stdout.write(`${JSON.stringify(receipt, null, args.includes("--json") ? 0 : 2)}\n`);
}
