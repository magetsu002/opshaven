import type { OpsHavenConfig } from "./config.js";
import { DeploymentExecutor } from "./deployment/apply.js";
import {
  runAppCommand as runBaseAppCommand,
  runDeployCommand,
  runDeploymentDoctor,
  renderApplicationRegistration,
  renderDeploymentApply,
  renderDeploymentFailure,
} from "./deployment/command.js";
import { DeploymentPlanner, type DeploymentPlannerOptions } from "./deployment/planning.js";
import type { DeploymentApplyResult } from "./deployment/model.js";

export * from "./deployment/model.js";
export * from "./deployment/planning.js";
export * from "./deployment/apply.js";
export {
  runDeployCommand,
  runDeploymentDoctor,
  renderApplicationRegistration,
  renderDeploymentApply,
  renderDeploymentFailure,
};
export type { DeploymentFailureContext, RegistrationNext } from "./deployment/command.js";

export async function runAppCommand(configPath: string, args: string[]): Promise<void> {
  if (!args.includes("--json") && args[0] === "add") {
    process.stderr.write(
      "Application registration updates protected local deployment authorization.\n"
      + "No remote changes are made during registration.\n"
      + "After saving, opshaven setup remote will synchronize only the required reviewed state.\n\n",
    );
  }
  await runBaseAppCommand(configPath, args);
}

export async function hasRegisteredApplications(configPath: string): Promise<boolean> {
  if (!configPath) return false;
  try {
    return (await (await DeploymentPlanner.load(configPath)).registry.list()).length > 0;
  } catch {
    return false;
  }
}

export class DeploymentCoordinator extends DeploymentPlanner {
  constructor(config: OpsHavenConfig, configPath: string, options: DeploymentPlannerOptions = {}) {
    super(config, configPath, options);
  }

  async applyPlan(planId: string, options: { approved: boolean; approvalToken?: string; actor?: string }): Promise<DeploymentApplyResult> {
    return await new DeploymentExecutor(this).apply(planId, options);
  }
}
