import type { OpsHavenConfig } from "./config.js";
import { DeploymentExecutor } from "./deployment/apply.js";
import { DeploymentPlanner, type DeploymentPlannerOptions } from "./deployment/planning.js";
import type { DeploymentApplyResult } from "./deployment/model.js";

export * from "./deployment/model.js";
export * from "./deployment/planning.js";
export * from "./deployment/apply.js";
export * from "./deployment/command.js";

export class DeploymentCoordinator extends DeploymentPlanner {
  constructor(config: OpsHavenConfig, configPath: string, options: DeploymentPlannerOptions = {}) {
    super(config, configPath, options);
  }

  async applyPlan(planId: string, options: { approved: boolean; approvalToken?: string; actor?: string }): Promise<DeploymentApplyResult> {
    return await new DeploymentExecutor(this).apply(planId, options);
  }
}
