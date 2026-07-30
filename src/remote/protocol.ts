import type { RemoteAuthorization } from "../approval.js";
import type { OpsHavenConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { PolicyEngine, type OperationName } from "../policy.js";

export interface RemoteRequest {
  version: 1;
  requestId: string;
  operation: OperationName | "get_state_fingerprint";
  resourceId: string;
  args: Readonly<Record<string, string | number | boolean>>;
  limits: { timeoutMs: number; maxBytes: number; maxLines: number };
  authorization?: RemoteAuthorization;
}
export interface RemoteSuccess {
  version: 1;
  requestId: string;
  ok: true;
  data: Record<string, unknown>;
  evidence: { startedAt: string; finishedAt: string; truncated: boolean; redactions: number };
}
export interface RemoteFailure {
  version: 1;
  requestId: string;
  ok: false;
  error: { code: string; message: string; retryable: boolean };
  evidence: { startedAt: string; finishedAt: string; truncated: boolean; redactions: number };
}
export type RemoteResponse = RemoteSuccess | RemoteFailure;

const REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/;
const RESOURCE_ID = /^[a-z][a-z0-9._-]{0,63}$/;
const ENCODED = /^[A-Za-z0-9_-]{1,8192}$/;
const OPERATIONS = new Set<string>([
  "get_host_summary",
  "get_deployed_commit",
  "get_service_status",
  "get_container_status",
  "get_runtime_config_status",
  "get_reverse_proxy_summary",
  "get_firewall_summary",
  "run_health_probe",
  "get_redacted_logs",
  "get_monitoring_status",
  "get_backup_status",
  "get_restore_readiness",
  "restart_service",
  "deploy_commit",
  "rollback_deployment",
  "get_state_fingerprint",
]);

function plain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function validArgumentValue(value: unknown): value is string | number | boolean {
  return typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value));
}

function validateAuthorization(value: unknown): void {
  if (!plain(value) || Object.keys(value).some((key) => key !== "payload" && key !== "signature") || typeof value.payload !== "string" || typeof value.signature !== "string" || !ENCODED.test(value.payload) || !ENCODED.test(value.signature)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote authorization is malformed.");
  }
}

export function parseRemoteRequest(value: unknown): RemoteRequest {
  if (!plain(value) || value.version !== 1 || typeof value.requestId !== "string" || !REQUEST_ID.test(value.requestId) || typeof value.operation !== "string" || !OPERATIONS.has(value.operation) || typeof value.resourceId !== "string" || !RESOURCE_ID.test(value.resourceId) || !plain(value.args) || !plain(value.limits)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Malformed remote request.");
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !["version", "requestId", "operation", "resourceId", "args", "limits", "authorization"].includes(key))) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote request has unknown fields.");
  }
  if (Object.values(value.args).some((item) => !validArgumentValue(item))) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote arguments must contain only finite primitive values.");
  }
  const timeoutMs = value.limits.timeoutMs;
  const maxBytes = value.limits.maxBytes;
  const maxLines = value.limits.maxLines;
  if (!Number.isInteger(timeoutMs) || (timeoutMs as number) < 100 || (timeoutMs as number) > 120000 || !Number.isInteger(maxBytes) || (maxBytes as number) < 1024 || (maxBytes as number) > 1048576 || !Number.isInteger(maxLines) || (maxLines as number) < 1 || (maxLines as number) > 5000) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote limits are invalid.");
  }
  if (value.authorization !== undefined) validateAuthorization(value.authorization);
  return value as unknown as RemoteRequest;
}

export function validateRemoteRequest(config: OpsHavenConfig, request: RemoteRequest): RemoteRequest {
  if (request.limits.timeoutMs !== config.limits.timeoutMs || request.limits.maxBytes !== config.limits.maxBytes || request.limits.maxLines !== config.limits.maxLines) {
    throw new OpsHavenError("POLICY_DENIED", "Remote limits must exactly match trusted configuration.");
  }
  if (request.operation === "get_state_fingerprint") {
    const target = config.resources.get(request.resourceId);
    if (!target || (target.kind !== "service" && target.kind !== "deployment")) {
      throw new OpsHavenError("POLICY_DENIED", "State fingerprint is unavailable for this resource.");
    }
    if (request.authorization || Object.keys(request.args).length !== 1 || request.args.resourceId !== request.resourceId) {
      throw new OpsHavenError("POLICY_DENIED", "Internal state requests must use the exact minimal argument set.");
    }
    return { ...request, args: Object.freeze({ resourceId: request.resourceId }), limits: { ...config.limits } };
  }
  const resolved = new PolicyEngine(config).resolve(request.operation, request.args);
  if (resolved.resourceId !== request.resourceId) {
    throw new OpsHavenError("POLICY_DENIED", "Remote envelope and operation resource IDs do not match.");
  }
  if (request.authorization && (!resolved.mutation || resolved.dryRun)) {
    throw new OpsHavenError("POLICY_DENIED", "Remote authorization is forbidden for read-only or dry-run operations.");
  }
  return { ...request, resourceId: resolved.resourceId, args: resolved.args, limits: resolved.limits };
}

export function parseRemoteResponse(value: unknown, requestId: string): RemoteResponse {
  if (!plain(value) || value.version !== 1 || value.requestId !== requestId || typeof value.ok !== "boolean" || !plain(value.evidence)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Malformed remote response.");
  }
  if (value.ok === true && plain(value.data)) return value as unknown as RemoteSuccess;
  if (value.ok === false && plain(value.error) && typeof value.error.code === "string" && typeof value.error.message === "string" && typeof value.error.retryable === "boolean") return value as unknown as RemoteFailure;
  throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Malformed remote response envelope.");
}
