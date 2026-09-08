import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { OpsHavenError, asOpsHavenError } from "./errors.js";
import type { ToolDefinition } from "./mcp.js";
import type { ResultEnvelope } from "./operations.js";
import type { DeploymentPlanner } from "./deployment/planning.js";
import { WorkspaceStore, type WorkspaceRecord } from "./workspace.js";
import {
  WorkspaceToolExecutor,
  discoverWorkspaceTasks,
  inspectWorkspaceSourceState,
  type DiscoveredTask,
} from "./workspace-tools.js";
import {
  VerificationStore,
  type VerificationEvidence,
  type WorkspaceSourceState,
} from "./workspace-verification.js";

const CONTINUITY_TOOL_NAMES = new Set(["project_state", "verify_workspace", "source_runtime_state", "prepare_verified_deployment"]);
const TIMEOUTS = new Set([1_000, 5_000, 30_000, 120_000, 600_000]);
const APP_ID = /^[a-z][a-z0-9-]{0,47}$/;

function schema(properties: Record<string, unknown>, required: string[] = []): Record<string, unknown> {
  return { type: "object", additionalProperties: false, properties, required };
}
const workspaceIdSchema = { type: "string", pattern: "^[a-z][a-z0-9._-]{0,63}$" };
const applicationIdSchema = { type: "string", pattern: "^[a-z][a-z0-9-]{0,47}$" };
const timeoutSchema = { type: "integer", enum: [1_000, 5_000, 30_000, 120_000, 600_000], default: 600_000 };

export const CONTINUITY_TOOL_DEFINITIONS: readonly ToolDefinition[] = [
  {
    name: "project_state",
    description: "Return exact local Git source state, ranked project tasks, and verification evidence bound to the current source state.",
    inputSchema: schema({ workspaceId: workspaceIdSchema }, ["workspaceId"]),
  },
  {
    name: "verify_workspace",
    description: "Run discovered primary verification tasks and record exact evidence against the current Git source state.",
    inputSchema: schema({
      workspaceId: workspaceIdSchema,
      taskIds: { type: "array", minItems: 1, maxItems: 8, items: { type: "string", minLength: 1, maxLength: 256 } },
      timeoutMs: timeoutSchema,
    }, ["workspaceId"]),
  },
  {
    name: "source_runtime_state",
    description: "Compare one local workspace revision with one configured application environment, deployed revision, service health, and rollback state.",
    inputSchema: schema({ workspaceId: workspaceIdSchema, applicationId: applicationIdSchema }, ["workspaceId", "applicationId"]),
  },
  {
    name: "prepare_verified_deployment",
    description: "Create an immutable deployment plan for the clean committed workspace HEAD only when all discovered primary verification tasks have current passing evidence.",
    inputSchema: schema({ workspaceId: workspaceIdSchema, applicationId: applicationIdSchema }, ["workspaceId", "applicationId"]),
  },
];

interface VerificationSummary {
  source: WorkspaceSourceState;
  primaryTasks: DiscoveredTask[];
  currentEvidence: VerificationEvidence[];
  passingPrimaryTaskIds: string[];
  complete: boolean;
}

function argsObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("INVALID_ARGUMENTS", "Tool arguments must be an object.");
  return value as Record<string, unknown>;
}

function stringValue(value: unknown, label: string, maximum = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.includes("\0")) throw new OpsHavenError("INVALID_ARGUMENTS", `${label} is invalid.`);
  return value;
}

function resultEnvelope(operation: string, startedAt: string, data: Record<string, unknown>): ResultEnvelope {
  return {
    ok: true,
    requestId: randomBytes(12).toString("hex"),
    operation,
    data,
    meta: { startedAt, finishedAt: new Date().toISOString(), dryRun: true, mutation: false, truncated: false, redactions: 0, auditRecorded: false },
  };
}

function errorEnvelope(operation: string, startedAt: string, error: unknown): ResultEnvelope {
  const safe = asOpsHavenError(error);
  return {
    ok: false,
    requestId: randomBytes(12).toString("hex"),
    operation,
    error: { code: safe.code, message: safe.message, retryable: safe.retryable, ...(safe.safeDetails ? { details: { ...safe.safeDetails } } : {}) },
    meta: { startedAt, finishedAt: new Date().toISOString(), dryRun: true, mutation: false, truncated: false, redactions: 0, auditRecorded: false },
  };
}

function requirePermission(workspace: WorkspaceRecord, permission: keyof WorkspaceRecord["permissions"]): void {
  if (!workspace.permissions[permission]) throw new OpsHavenError("POLICY_DENIED", `Workspace permission "${permission}" is disabled.`);
}

async function verificationSummary(
  workspace: WorkspaceRecord,
  verification: VerificationStore,
  signal?: AbortSignal,
): Promise<VerificationSummary> {
  const source = await inspectWorkspaceSourceState(workspace, signal);
  const tasks = await discoverWorkspaceTasks(workspace);
  const primaryTasks = tasks.filter((task) => task.category === "primary_verification");
  const currentEvidence = await verification.current(workspace.id, source);
  const passing = new Set(currentEvidence.filter((item) => item.passed).map((item) => item.taskId));
  const passingPrimaryTaskIds = primaryTasks.filter((task) => passing.has(task.id)).map((task) => task.id);
  return {
    source,
    primaryTasks,
    currentEvidence,
    passingPrimaryTaskIds,
    complete: primaryTasks.length > 0 && passingPrimaryTaskIds.length === primaryTasks.length,
  };
}

async function gitOutput(workspace: WorkspaceRecord, args: string[]): Promise<{ code: number | null; stdout: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn("/usr/bin/git", ["-C", workspace.root, ...args], {
      cwd: workspace.root,
      shell: false,
      stdio: ["ignore", "pipe", "ignore"],
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    });
    let stdout = "";
    child.stdout.on("data", (chunk: Uint8Array) => { if (stdout.length < 65536) stdout += Buffer.from(chunk).toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code: number | null) => resolve({ code, stdout }));
  });
}

async function sourceRelationship(workspace: WorkspaceRecord, local: string, deployed: string): Promise<Record<string, unknown>> {
  if (!/^[a-f0-9]{40}$/i.test(deployed)) return { kind: "unknown", reason: "Configured environment did not report a complete deployed Git revision." };
  if (local === deployed.toLowerCase()) return { kind: "match", aheadBy: 0, behindBy: 0 };
  const exists = await gitOutput(workspace, ["cat-file", "-e", `${deployed}^{commit}`]);
  if (exists.code !== 0) return { kind: "unknown", reason: "Deployed revision is not present in the local repository object graph." };
  const deployedAncestor = await gitOutput(workspace, ["merge-base", "--is-ancestor", deployed, local]);
  if (deployedAncestor.code === 0) {
    const count = await gitOutput(workspace, ["rev-list", "--count", `${deployed}..${local}`]);
    return { kind: "local_ahead", aheadBy: Number(count.stdout.trim()) || 0, behindBy: 0 };
  }
  const localAncestor = await gitOutput(workspace, ["merge-base", "--is-ancestor", local, deployed]);
  if (localAncestor.code === 0) {
    const count = await gitOutput(workspace, ["rev-list", "--count", `${local}..${deployed}`]);
    return { kind: "local_behind", aheadBy: 0, behindBy: Number(count.stdout.trim()) || 0 };
  }
  const counts = await gitOutput(workspace, ["rev-list", "--left-right", "--count", `${deployed}...${local}`]);
  const [behind, ahead] = counts.stdout.trim().split(/\s+/).map((value) => Number(value) || 0);
  return { kind: "diverged", aheadBy: ahead ?? 0, behindBy: behind ?? 0 };
}

function taskGroups(tasks: DiscoveredTask[]): Record<string, DiscoveredTask[]> {
  return {
    primaryVerification: tasks.filter((task) => task.category === "primary_verification"),
    development: tasks.filter((task) => task.category === "development"),
    advancedMaintenance: tasks.filter((task) => task.category === "advanced_maintenance"),
    other: tasks.filter((task) => task.category === "other"),
  };
}

export class ContinuityToolExecutor {
  constructor(
    readonly workspace = new WorkspaceToolExecutor(),
    readonly planner?: DeploymentPlanner,
  ) {}

  static handles(name: string): boolean { return CONTINUITY_TOOL_NAMES.has(name); }

  private async projectState(workspace: WorkspaceRecord, signal?: AbortSignal): Promise<Record<string, unknown>> {
    requirePermission(workspace, "read");
    const tasks = await discoverWorkspaceTasks(workspace);
    const summary = await verificationSummary(workspace, this.workspace.verification, signal);
    const allEvidence = await this.workspace.verification.load(workspace.id);
    return {
      workspace: { id: workspace.id, name: workspace.name, root: workspace.root, project: workspace.project, permissions: workspace.permissions },
      source: summary.source,
      tasks: taskGroups(tasks),
      verification: {
        complete: summary.complete,
        requiredPrimaryTaskIds: summary.primaryTasks.map((task) => task.id),
        passingPrimaryTaskIds: summary.passingPrimaryTaskIds,
        currentEvidence: summary.currentEvidence,
        staleEvidenceCount: allEvidence.length - summary.currentEvidence.length,
      },
    };
  }

  async execute(operation: string, rawArgs: unknown, _approvalToken?: string, _actor?: string, signal?: AbortSignal): Promise<ResultEnvelope> {
    const startedAt = new Date().toISOString();
    try {
      if (!CONTINUITY_TOOL_NAMES.has(operation)) throw new OpsHavenError("UNKNOWN_OPERATION", "Unknown source-to-runtime operation.");
      const args = argsObject(rawArgs);
      const workspaceId = stringValue(args.workspaceId, "workspaceId", 64);
      const workspace = await this.workspace.store.get(workspaceId);

      if (operation === "project_state") return resultEnvelope(operation, startedAt, await this.projectState(workspace, signal));

      if (operation === "verify_workspace") {
        requirePermission(workspace, "read");
        requirePermission(workspace, "tasks");
        const tasks = (await discoverWorkspaceTasks(workspace)).filter((task) => task.category === "primary_verification");
        if (tasks.length === 0) throw new OpsHavenError("POLICY_DENIED", "No primary verification tasks were discovered from project metadata.");
        let selected = tasks;
        if (args.taskIds !== undefined) {
          if (!Array.isArray(args.taskIds) || args.taskIds.length < 1 || args.taskIds.length > 8 || args.taskIds.some((item) => typeof item !== "string")) throw new OpsHavenError("INVALID_ARGUMENTS", "taskIds must contain 1-8 discovered primary verification task IDs.");
          const requested = new Set(args.taskIds as string[]);
          selected = tasks.filter((task) => requested.has(task.id));
          if (selected.length !== requested.size) throw new OpsHavenError("POLICY_DENIED", "verify_workspace accepts only discovered primary verification tasks.");
        }
        const timeoutMs = args.timeoutMs === undefined ? 600_000 : Number(args.timeoutMs);
        if (!TIMEOUTS.has(timeoutMs)) throw new OpsHavenError("INVALID_ARGUMENTS", "timeoutMs must use a supported bounded timeout.");
        const runs: Record<string, unknown>[] = [];
        for (const task of selected) {
          const result = await this.workspace.execute("run_task", { workspaceId, taskId: task.id, timeoutMs }, undefined, undefined, signal);
          runs.push({ taskId: task.id, ok: result.ok, data: result.data ?? null, error: result.error ?? null });
          if (signal?.aborted) break;
        }
        const state = await this.projectState(workspace, signal);
        return resultEnvelope(operation, startedAt, { runs, state });
      }

      const applicationId = stringValue(args.applicationId, "applicationId", 48);
      if (!APP_ID.test(applicationId)) throw new OpsHavenError("INVALID_ARGUMENTS", "applicationId is invalid.");
      if (!this.planner) throw new OpsHavenError("CONFIG_INVALID", "Remote deployment continuity is unavailable because no configured application environment is loaded.");
      requirePermission(workspace, "read");
      const app = await this.planner.registry.get(applicationId);
      const [summary, runtime] = await Promise.all([
        verificationSummary(workspace, this.workspace.verification, signal),
        this.planner.inspect(app),
      ]);
      const difference = await sourceRelationship(workspace, summary.source.head, runtime.currentRevision);
      const continuity = {
        workspace: { id: workspace.id, name: workspace.name, source: summary.source },
        verification: {
          complete: summary.complete,
          requiredPrimaryTaskIds: summary.primaryTasks.map((task) => task.id),
          passingPrimaryTaskIds: summary.passingPrimaryTaskIds,
          currentEvidence: summary.currentEvidence,
        },
        application: {
          id: app.id,
          name: app.name,
          targetLabel: app.targetLabel,
          hostResourceId: app.hostResourceId,
          deploymentResourceId: app.deploymentResourceId,
          serviceResourceId: app.serviceResourceId,
          probeResourceId: app.probeResourceId,
        },
        runtime: {
          deployedRevision: runtime.currentRevision,
          sourceRepositoryRevision: runtime.sourceRepositoryRevision,
          sourceRepositoryDirty: runtime.sourceRepositoryDirty,
          activeReleaseId: runtime.activeReleaseId,
          service: {
            identifier: runtime.serviceIdentifier,
            activeState: runtime.serviceActiveState,
            subState: runtime.serviceSubState,
            exitStatus: runtime.serviceExitStatus,
          },
          health: {
            reachable: runtime.healthReachable,
            expected: runtime.healthExpected,
            statusCode: runtime.healthStatusCode,
          },
          rollback: {
            available: runtime.rollbackAvailable,
            releaseId: runtime.activeReleaseId,
            revision: runtime.currentRevision,
          },
        },
        difference,
      };

      if (operation === "source_runtime_state") return resultEnvelope(operation, startedAt, continuity);

      if (!summary.source.clean) throw new OpsHavenError("POLICY_DENIED", "Workspace has uncommitted or untracked changes. Commit or discard them before preparing deployment.");
      if (!summary.complete) throw new OpsHavenError("POLICY_DENIED", "Current workspace revision does not have passing evidence for every discovered primary verification task.");
      const stored = await this.planner.createPlan(app.id, summary.source.head);
      return resultEnvelope(operation, startedAt, {
        continuity,
        plan: {
          planId: stored.planId,
          applicationId: stored.plan.applicationId,
          currentRevision: stored.plan.currentRevision,
          targetRevision: stored.plan.targetRevision,
          observedStateFingerprint: stored.plan.observedStateFingerprint,
          expiresAt: stored.plan.expiresAt,
          rollback: stored.plan.rollback,
        },
      });
    } catch (error) {
      return errorEnvelope(operation, startedAt, error);
    }
  }
}
