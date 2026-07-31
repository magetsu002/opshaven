import { randomBytes } from "node:crypto";
import { ApprovalService, operationDigest, type RemoteAuthorization } from "./approval.js";
import { AuditLog } from "./audit.js";
import { sha256 } from "./canonical.js";
import type { HostResource, OpsHavenConfig } from "./config.js";
import { asOpsHavenError, OpsHavenError } from "./errors.js";
import { PolicyEngine, type ResolvedOperation } from "./policy.js";
import { sanitizeOutput } from "./redaction.js";
import type { RemoteRequest, RemoteResponse } from "./remote/protocol.js";
import { SshTransport } from "./transport/ssh.js";

export interface ResultEnvelope {
  ok: boolean;
  requestId: string;
  operation: string;
  resourceId?: string;
  data?: Record<string, unknown>;
  error?: { code: string; message: string; retryable: boolean; details?: Record<string, unknown> };
  meta: { startedAt: string; finishedAt: string; dryRun: boolean; mutation: boolean; truncated: boolean; redactions: number; auditRecorded: boolean };
}
export interface RemoteTransport { execute(host: HostResource, request: RemoteRequest, signal?: AbortSignal): Promise<RemoteResponse> }

function cancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new OpsHavenError("TIMEOUT", "Operation was cancelled before remote execution.", true);
}
function sanitizeValue(value: unknown, config: OpsHavenConfig): { value: unknown; redactions: number; truncated: boolean } {
  if (typeof value === "string") {
    const result = sanitizeOutput(value, config.limits, config.secretFingerprints);
    return { value: result.text, redactions: result.redactions, truncated: result.truncated };
  }
  if (Array.isArray(value)) {
    let redactions = 0; let truncated = false;
    const output = value.map((item) => { const safe = sanitizeValue(item, config); redactions += safe.redactions; truncated ||= safe.truncated; return safe.value; });
    return { value: output, redactions, truncated };
  }
  if (value && typeof value === "object") {
    let redactions = 0; let truncated = false; const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) { const safe = sanitizeValue(item, config); output[key] = safe.value; redactions += safe.redactions; truncated ||= safe.truncated; }
    return { value: output, redactions, truncated };
  }
  return { value, redactions: 0, truncated: false };
}

export class OperationService {
  readonly policy: PolicyEngine;
  readonly approvals: ApprovalService;
  readonly audit: AuditLog;
  private readonly transport: RemoteTransport;

  constructor(readonly config: OpsHavenConfig, transport?: RemoteTransport, configPath?: string) {
    this.policy = new PolicyEngine(config);
    this.approvals = new ApprovalService(config.approvals);
    this.audit = new AuditLog(config.audit.path);
    this.transport = transport ?? new SshTransport(configPath ? { config, configPath, mode: "controlled" } : undefined);
  }

  private host(id: string): HostResource {
    const host = this.config.resources.get(id);
    if (!host || host.kind !== "host") throw new OpsHavenError("CONFIG_INVALID", "Resolved host is invalid.");
    return host;
  }
  private request(operation: ResolvedOperation, authorization?: RemoteAuthorization): RemoteRequest {
    return { version: 1, requestId: randomBytes(12).toString("hex"), operation: operation.operation, resourceId: operation.resourceId, args: operation.args, limits: operation.limits, ...(authorization ? { authorization } : {}) };
  }

  async planMutation(operationName: string, args: unknown, signal?: AbortSignal): Promise<ResolvedOperation> {
    cancelled(signal);
    const initial = this.policy.resolve(operationName, args);
    if (!initial.mutation || initial.dryRun) throw new OpsHavenError("APPROVAL_INVALID", "Only non-dry-run mutations require a plan.");
    const stateRequest: RemoteRequest = { version: 1, requestId: randomBytes(12).toString("hex"), operation: "get_state_fingerprint", resourceId: initial.resourceId, args: Object.freeze({ resourceId: initial.resourceId }), limits: initial.limits };
    const state = await this.transport.execute(this.host(initial.hostId), stateRequest, signal);
    if (!state.ok) throw new OpsHavenError("REMOTE_OPERATION_FAILED", state.error.message, state.error.retryable);
    return this.policy.resolve(operationName, args, sha256(state.data));
  }

  async execute(operationName: string, args: unknown, approvalToken?: string, actor = "mcp-client", signal?: AbortSignal): Promise<ResultEnvelope> {
    const startedAt = new Date().toISOString();
    let resolved: ResolvedOperation | undefined;
    let approvalDigest: string | undefined;
    let authorization: RemoteAuthorization | undefined;
    let auditRecorded = false;
    try {
      cancelled(signal);
      resolved = this.policy.resolve(operationName, args);
      if (resolved.mutation && !resolved.dryRun) {
        if (!approvalToken) throw new OpsHavenError("APPROVAL_REQUIRED", "A human approval token is required.");
        resolved = await this.planMutation(operationName, args, signal);
        cancelled(signal);
        const consumed = await this.approvals.consume(approvalToken, resolved);
        approvalDigest = consumed.digest;
        authorization = consumed.authorization;
      }
      cancelled(signal);
      const remoteRequest = this.request(resolved, authorization);
      const response = await this.transport.execute(this.host(resolved.hostId), remoteRequest, signal);
      if (!response.ok) throw new OpsHavenError("REMOTE_OPERATION_FAILED", response.error.message, response.error.retryable, { remoteCode: response.error.code });
      const safe = sanitizeValue(response.data, this.config);
      const data = safe.value as Record<string, unknown>;
      await this.audit.append({ timestamp: new Date().toISOString(), requestId: remoteRequest.requestId, actor, operation: resolved.operation, resourceId: resolved.resourceId, mutation: resolved.mutation, dryRun: resolved.dryRun, ...(approvalDigest ? { approvalDigest } : {}), outcome: "success", evidenceDigest: sha256(data) });
      auditRecorded = true;
      return { ok: true, requestId: remoteRequest.requestId, operation: resolved.operation, resourceId: resolved.resourceId, data, meta: { startedAt, finishedAt: new Date().toISOString(), dryRun: resolved.dryRun, mutation: resolved.mutation, truncated: response.evidence.truncated || safe.truncated, redactions: response.evidence.redactions + safe.redactions, auditRecorded } };
    } catch (error) {
      const safe = asOpsHavenError(error);
      const requestId = randomBytes(12).toString("hex");
      if (resolved) {
        try {
          await this.audit.append({ timestamp: new Date().toISOString(), requestId, actor, operation: resolved.operation, resourceId: resolved.resourceId, mutation: resolved.mutation, dryRun: resolved.dryRun, ...(approvalDigest ? { approvalDigest } : {}), outcome: safe.code === "APPROVAL_REQUIRED" || safe.code.startsWith("APPROVAL_") || safe.code === "POLICY_DENIED" ? "denied" : "failure", errorCode: safe.code });
          auditRecorded = true;
        } catch { auditRecorded = false; }
      }
      return { ok: false, requestId, operation: operationName, ...(resolved ? { resourceId: resolved.resourceId } : {}), error: { code: safe.code, message: safe.message, retryable: safe.retryable, ...(safe.safeDetails ? { details: { ...safe.safeDetails } } : {}) }, meta: { startedAt, finishedAt: new Date().toISOString(), dryRun: resolved?.dryRun ?? false, mutation: resolved?.mutation ?? false, truncated: false, redactions: 0, auditRecorded } };
    }
  }

  async createApproval(operationName: string, args: unknown, ttlSeconds?: number): Promise<{ token: string; digest: string; expiresAt: string; operationDigest: string }> {
    const resolved = await this.planMutation(operationName, args);
    const created = await this.approvals.create(resolved, ttlSeconds);
    return { ...created, operationDigest: operationDigest(resolved) };
  }
}
