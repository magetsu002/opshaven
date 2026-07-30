import type { OperationName } from "../policy.js";
import type { RemoteAuthorization } from "../approval.js";
import { OpsHavenError } from "../errors.js";

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

const ID = /^[A-Za-z0-9._-]{1,128}$/;
function plain(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }

export function parseRemoteRequest(value: unknown): RemoteRequest {
  if (!plain(value) || value.version !== 1 || typeof value.requestId !== "string" || !ID.test(value.requestId) || typeof value.operation !== "string" || typeof value.resourceId !== "string" || !ID.test(value.resourceId) || !plain(value.args) || !plain(value.limits)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Malformed remote request.");
  const keys = Object.keys(value);
  if (keys.some((key) => !["version", "requestId", "operation", "resourceId", "args", "limits", "authorization"].includes(key))) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote request has unknown fields.");
  const timeoutMs = value.limits.timeoutMs;
  const maxBytes = value.limits.maxBytes;
  const maxLines = value.limits.maxLines;
  if (!Number.isInteger(timeoutMs) || !Number.isInteger(maxBytes) || !Number.isInteger(maxLines)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote limits are invalid.");
  return value as unknown as RemoteRequest;
}

export function parseRemoteResponse(value: unknown, requestId: string): RemoteResponse {
  if (!plain(value) || value.version !== 1 || value.requestId !== requestId || typeof value.ok !== "boolean" || !plain(value.evidence)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Malformed remote response.");
  if (value.ok === true && plain(value.data)) return value as unknown as RemoteSuccess;
  if (value.ok === false && plain(value.error) && typeof value.error.code === "string" && typeof value.error.message === "string" && typeof value.error.retryable === "boolean") return value as unknown as RemoteFailure;
  throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Malformed remote response envelope.");
}
