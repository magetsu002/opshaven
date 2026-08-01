import { sha256 } from "../canonical.js";
import { OpsHavenError } from "../errors.js";
import {
  applicationBinding,
  deploymentPlanId,
  type DeploymentApplication,
  type DeploymentApplyResult,
  type DeploymentOutcome,
  type DeploymentPlan,
  type ObservedDeploymentState,
  type StoredDeploymentPlan,
} from "./model.js";
import { DeploymentPlanner, deploymentAudit, requireHealthyDeploymentAudit } from "./planning.js";

export class DeploymentExecutor {
  constructor(readonly planner: DeploymentPlanner) {}

  private async rollback(plan: DeploymentPlan, app: DeploymentApplication, actor: string): Promise<{ ok: boolean; observed: ObservedDeploymentState | null }> {
    await deploymentAudit(this.planner.config, {
      operation: "deployment_rollback_start", applicationId: app.id, planId: deploymentPlanId(plan), sourceRevision: plan.targetRevision, targetRevision: plan.currentRevision,
      targetIdentity: plan.target.identityDigest, authorizationIdentity: plan.requiredAuthorization.operatorProfileDigest, operationResult: "success", mutation: true,
      evidence: { releaseId: plan.rollback.releaseId },
    }).catch(() => undefined);
    try {
      const args = { resourceId: app.deploymentResourceId, releaseId: plan.rollback.releaseId, dryRun: false };
      const approval = await this.planner.client.createApproval("rollback_deployment", args);
      const result = await this.planner.client.execute("rollback_deployment", args, approval.token, actor);
      if (!result.ok) throw new OpsHavenError("REMOTE_OPERATION_FAILED", result.error?.message ?? "Rollback failed safely.");
      const observed = await this.planner.inspect(app);
      const ok = observed.currentRevision === plan.currentRevision && observed.serviceActiveState === "active" && observed.healthExpected;
      await deploymentAudit(this.planner.config, {
        operation: "deployment_rollback_result", applicationId: app.id, planId: deploymentPlanId(plan), sourceRevision: plan.targetRevision, targetRevision: plan.currentRevision,
        targetIdentity: plan.target.identityDigest, authorizationIdentity: plan.requiredAuthorization.operatorProfileDigest, operationResult: ok ? "success" : "failure", mutation: true,
        finalOutcome: ok ? "DEPLOYMENT_FAILED_ROLLED_BACK" : "DEPLOYMENT_FAILED_ROLLBACK_FAILED", evidence: { activeRevision: observed.currentRevision, healthExpected: observed.healthExpected },
      });
      return { ok, observed };
    } catch (error) {
      await deploymentAudit(this.planner.config, {
        operation: "deployment_rollback_result", applicationId: app.id, planId: deploymentPlanId(plan), sourceRevision: plan.targetRevision, targetRevision: plan.currentRevision,
        targetIdentity: plan.target.identityDigest, authorizationIdentity: plan.requiredAuthorization.operatorProfileDigest, operationResult: "failure", mutation: true,
        finalOutcome: "DEPLOYMENT_FAILED_ROLLBACK_FAILED", evidence: { errorCode: error instanceof OpsHavenError ? error.code : "INTERNAL_ERROR", messageDigest: sha256(error instanceof Error ? error.message : "rollback failed safely") },
      }).catch(() => undefined);
      return { ok: false, observed: null };
    }
  }

  private async operationAudit(plan: DeploymentPlan, outcome: "success" | "failure"): Promise<void> {
    for (const operation of plan.operations) {
      await deploymentAudit(this.planner.config, {
        operation: `deployment_operation_${operation.kind}`, applicationId: plan.applicationId, planId: deploymentPlanId(plan), sourceRevision: plan.currentRevision, targetRevision: plan.targetRevision,
        targetIdentity: plan.target.identityDigest, authorizationIdentity: plan.requiredAuthorization.operatorProfileDigest, operationResult: outcome,
        mutation: operation.mutation !== "none", evidence: { operation: operation.kind, result: outcome, permittedResourcesDigest: sha256(operation.permittedResources) },
      });
    }
  }

  private result(stored: StoredDeploymentPlan, outcome: DeploymentOutcome, failure: string | null, rollbackAttempted: boolean, observed: ObservedDeploymentState | null): DeploymentApplyResult {
    return {
      planId: stored.planId,
      applicationId: stored.plan.applicationId,
      targetRevision: stored.plan.targetRevision,
      currentRevision: stored.plan.currentRevision,
      outcome,
      failure,
      rollbackAttempted,
      activeRevision: observed?.currentRevision ?? "unknown",
      healthVerified: observed?.healthExpected === true && observed.serviceActiveState === "active",
    };
  }

  async apply(planId: string, options: { approved: boolean; approvalToken?: string; actor?: string }): Promise<DeploymentApplyResult> {
    if (!options.approved) throw new OpsHavenError("APPROVAL_REQUIRED", "Deployment plan was not explicitly approved. No changes were made.");
    const stored = await this.planner.plans.load(planId);
    const app = await this.planner.registry.get(stored.plan.applicationId);
    applicationBinding(this.planner.config, app);
    const actor = options.actor ?? `operator:${stored.plan.requiredAuthorization.operatorProfileDigest.slice(0, 16)}`;
    const releaseLock = await this.planner.plans.acquireApplicationLock(app.id, { schemaVersion: 1, applicationId: app.id, planId, acquiredAt: new Date(this.planner.now()).toISOString() });
    let retainLock = false;
    try {
      if (await this.planner.plans.replayed(planId)) throw new OpsHavenError("APPROVAL_REPLAYED", "Deployment plan was already applied or entered recovery state. No changes were made.");
      await requireHealthyDeploymentAudit(this.planner.config);
      const before = await this.planner.revalidate(stored, app);
      await deploymentAudit(this.planner.config, {
        operation: "deployment_apply_approval", applicationId: app.id, planId, sourceRevision: stored.plan.currentRevision, targetRevision: stored.plan.targetRevision,
        targetIdentity: stored.plan.target.identityDigest, authorizationIdentity: stored.plan.requiredAuthorization.operatorProfileDigest, operationResult: "success", mutation: false,
        evidence: { approvalMechanism: stored.plan.requiredAuthorization.mechanism },
      });
      await deploymentAudit(this.planner.config, {
        operation: "deployment_apply_start", applicationId: app.id, planId, sourceRevision: stored.plan.currentRevision, targetRevision: stored.plan.targetRevision,
        targetIdentity: stored.plan.target.identityDigest, authorizationIdentity: stored.plan.requiredAuthorization.operatorProfileDigest, operationResult: "success", mutation: true,
        evidence: { observedStateFingerprint: stored.plan.observedStateFingerprint },
      });
      await this.planner.plans.markStarted({ schemaVersion: 1, planId, applicationId: app.id, operatorProfileDigest: stored.plan.requiredAuthorization.operatorProfileDigest, startedAt: new Date(this.planner.now()).toISOString() });
      retainLock = true;

      const args: Record<string, string | boolean> = { resourceId: app.deploymentResourceId, commit: stored.plan.targetRevision, expectedCurrentCommit: stored.plan.currentRevision, dryRun: false };
      const approvalToken = options.approvalToken ?? (await this.planner.client.createApproval("deploy_commit", args)).token;
      const remote = await this.planner.client.execute("deploy_commit", args, approvalToken, actor);
      let observed: ObservedDeploymentState | null = null;
      try { observed = await this.planner.inspect(app); } catch { observed = null; }
      const targetHealthy = remote.ok && observed?.currentRevision === stored.plan.targetRevision && observed.serviceActiveState === "active" && observed.healthExpected;

      if (targetHealthy && observed) {
        try {
          await this.operationAudit(stored.plan, "success");
          await deploymentAudit(this.planner.config, {
            operation: "deployment_completion", applicationId: app.id, planId, sourceRevision: stored.plan.currentRevision, targetRevision: stored.plan.targetRevision,
            targetIdentity: stored.plan.target.identityDigest, authorizationIdentity: stored.plan.requiredAuthorization.operatorProfileDigest, operationResult: "success", mutation: true,
            finalOutcome: "DEPLOYMENT_SUCCEEDED", evidence: { activeRevision: observed.currentRevision, healthExpected: observed.healthExpected },
          });
          const completed = this.result(stored, "DEPLOYMENT_SUCCEEDED", null, false, observed);
          await this.planner.plans.markResult({ schemaVersion: 1, planId, applicationId: app.id, finishedAt: new Date(this.planner.now()).toISOString(), outcome: completed.outcome, evidenceDigest: sha256(completed) });
          retainLock = false;
          return completed;
        } catch (error) {
          const recovery = await this.rollback(stored.plan, app, actor);
          const outcome: DeploymentOutcome = recovery.ok ? "DEPLOYMENT_FAILED_ROLLED_BACK" : "DEPLOYMENT_FAILED_ROLLBACK_FAILED";
          const failed = this.result(stored, outcome, error instanceof Error ? error.message : "Post-deployment evidence could not be recorded safely.", true, recovery.observed);
          await this.planner.plans.markResult({ schemaVersion: 1, planId, applicationId: app.id, finishedAt: new Date(this.planner.now()).toISOString(), outcome, evidenceDigest: sha256(failed) }).catch(() => undefined);
          retainLock = outcome === "DEPLOYMENT_FAILED_ROLLBACK_FAILED";
          return failed;
        }
      }

      const priorHealthy = observed?.currentRevision === before.currentRevision && observed.serviceActiveState === "active" && observed.healthExpected;
      const clearlyPreActivation = !remote.ok && /commit|revision|repository|disk|build|worktree|approval|authorization/i.test(remote.error?.message ?? "");
      if (priorHealthy && clearlyPreActivation) {
        await this.operationAudit(stored.plan, "failure").catch(() => undefined);
        const notStarted = this.result(stored, "DEPLOYMENT_NOT_STARTED", remote.error?.message ?? "Deployment did not start.", false, observed);
        await deploymentAudit(this.planner.config, {
          operation: "deployment_failure", applicationId: app.id, planId, sourceRevision: stored.plan.currentRevision, targetRevision: stored.plan.targetRevision,
          targetIdentity: stored.plan.target.identityDigest, authorizationIdentity: stored.plan.requiredAuthorization.operatorProfileDigest, operationResult: "failure", mutation: true,
          finalOutcome: notStarted.outcome, evidence: { activeRevision: notStarted.activeRevision, failureDigest: sha256(notStarted.failure ?? "deployment did not start") },
        });
        await this.planner.plans.markResult({ schemaVersion: 1, planId, applicationId: app.id, finishedAt: new Date(this.planner.now()).toISOString(), outcome: notStarted.outcome, evidenceDigest: sha256(notStarted) });
        retainLock = false;
        return notStarted;
      }

      const recovery = priorHealthy ? { ok: true, observed } : await this.rollback(stored.plan, app, actor);
      const outcome: DeploymentOutcome = recovery.ok ? "DEPLOYMENT_FAILED_ROLLED_BACK" : "DEPLOYMENT_FAILED_ROLLBACK_FAILED";
      await this.operationAudit(stored.plan, "failure").catch(() => undefined);
      const failed = this.result(stored, outcome, remote.error?.message ?? "Post-activation verification failed.", true, recovery.observed);
      await deploymentAudit(this.planner.config, {
        operation: "deployment_failure", applicationId: app.id, planId, sourceRevision: stored.plan.currentRevision, targetRevision: stored.plan.targetRevision,
        targetIdentity: stored.plan.target.identityDigest, authorizationIdentity: stored.plan.requiredAuthorization.operatorProfileDigest, operationResult: "failure", mutation: true,
        finalOutcome: outcome, evidence: { activeRevision: failed.activeRevision, rollbackAttempted: true, failureDigest: sha256(failed.failure ?? "deployment failed safely") },
      }).catch(() => undefined);
      await this.planner.plans.markResult({ schemaVersion: 1, planId, applicationId: app.id, finishedAt: new Date(this.planner.now()).toISOString(), outcome, evidenceDigest: sha256(failed) }).catch(() => undefined);
      retainLock = outcome === "DEPLOYMENT_FAILED_ROLLBACK_FAILED";
      return failed;
    } finally {
      if (!retainLock) await releaseLock();
    }
  }
}
