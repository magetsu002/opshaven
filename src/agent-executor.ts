import { OpsHavenError } from "./errors.js";
import type { ToolExecutor } from "./mcp.js";
import type { ResultEnvelope } from "./operations.js";
import { WorkspaceToolExecutor } from "./workspace-tools.js";

function unavailable(operation: string): ResultEnvelope {
  const error = new OpsHavenError("CONFIG_INVALID", "Remote operations are unavailable because no remote OpsHaven configuration is loaded.");
  const now = new Date().toISOString();
  return {
    ok: false,
    requestId: "remote-unavailable",
    operation,
    error: { code: error.code, message: error.message, retryable: error.retryable },
    meta: { startedAt: now, finishedAt: now, dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: false },
  };
}

export class AgentToolExecutor implements ToolExecutor {
  constructor(
    private readonly workspace: WorkspaceToolExecutor,
    private readonly remote?: ToolExecutor,
  ) {}

  async execute(operation: string, args: unknown, approvalToken?: string, actor?: string, signal?: AbortSignal): Promise<ResultEnvelope> {
    if (WorkspaceToolExecutor.handles(operation)) return await this.workspace.execute(operation, args, approvalToken, actor, signal);
    if (!this.remote) return unavailable(operation);
    return await this.remote.execute(operation, args, approvalToken, actor, signal);
  }
}
