import { OpsHavenError } from "../errors.js";
import { executeRemoteSetup } from "./engine.js";
import { buildRemoteSetupPlan, formatRemoteSetupPlan, loadRemoteSetupConfig } from "./remote.js";

function value(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}

export async function runRemoteSetup(args: readonly string[]): Promise<void> {
  const configPath = value(args, "--config");
  if (!configPath) throw new OpsHavenError("CONFIG_INVALID", "Remote setup requires --config with an absolute setup configuration path.");
  const config = await loadRemoteSetupConfig(configPath);
  const plan = buildRemoteSetupPlan(config);
  const json = args.includes("--json");
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
