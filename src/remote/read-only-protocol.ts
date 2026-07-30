import type { OpsHavenConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { READ_ONLY_OPERATIONS, ReadOnlyPolicyEngine, type ReadOnlyOperationName } from "./read-only-policy.js";

export interface ReadOnlyRemoteRequest {
  version: 1;
  requestId: string;
  operation: ReadOnlyOperationName;
  resourceId: string;
  args: Readonly<Record<string, string | number | boolean>>;
  limits: { timeoutMs: number; maxBytes: number; maxLines: number };
}

export interface ReadOnlyRemoteSuccess {
  version: 1;
  requestId: string;
  ok: true;
  data: Record<string, unknown>;
  evidence: { startedAt: string; finishedAt: string; truncated: boolean; redactions: number };
}

export interface ReadOnlyRemoteFailure {
  version: 1;
  requestId: string;
  ok: false;
  error: { code: string; message: string; retryable: boolean };
  evidence: { startedAt: string; finishedAt: string; truncated: boolean; redactions: number };
}

export type ReadOnlyRemoteResponse = ReadOnlyRemoteSuccess | ReadOnlyRemoteFailure;

const REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/;
const RESOURCE_ID = /^[a-z][a-z0-9._-]{0,63}$/;
const OPERATIONS = new Set<string>(READ_ONLY_OPERATIONS);

function plain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function validArgumentValue(value: unknown): value is string | number | boolean {
  return typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value));
}

export function parseReadOnlyRemoteRequest(value: unknown): ReadOnlyRemoteRequest {
  if (
    !plain(value)
    || value.version !== 1
    || typeof value.requestId !== "string"
    || !REQUEST_ID.test(value.requestId)
    || typeof value.operation !== "string"
    || !OPERATIONS.has(value.operation)
    || typeof value.resourceId !== "string"
    || !RESOURCE_ID.test(value.resourceId)
    || !plain(value.args)
    || !plain(value.limits)
  ) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Malformed read-only remote request.");
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !["version", "requestId", "operation", "resourceId", "args", "limits"].includes(key))) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Read-only remote request has unknown fields.");
  }
  if (Object.values(value.args).some((item) => !validArgumentValue(item))) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Read-only remote arguments must contain only finite primitive values.");
  }
  const timeoutMs = value.limits.timeoutMs;
  const maxBytes = value.limits.maxBytes;
  const maxLines = value.limits.maxLines;
  if (
    !Number.isInteger(timeoutMs)
    || (timeoutMs as number) < 100
    || (timeoutMs as number) > 120000
    || !Number.isInteger(maxBytes)
    || (maxBytes as number) < 1024
    || (maxBytes as number) > 1048576
    || !Number.isInteger(maxLines)
    || (maxLines as number) < 1
    || (maxLines as number) > 5000
  ) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Read-only remote limits are invalid.");
  }
  return value as unknown as ReadOnlyRemoteRequest;
}

export function validateReadOnlyRemoteRequest(config: OpsHavenConfig, request: ReadOnlyRemoteRequest): ReadOnlyRemoteRequest {
  if (
    request.limits.timeoutMs !== config.limits.timeoutMs
    || request.limits.maxBytes !== config.limits.maxBytes
    || request.limits.maxLines !== config.limits.maxLines
  ) {
    throw new OpsHavenError("POLICY_DENIED", "Read-only remote limits must exactly match trusted configuration.");
  }
  const resolved = new ReadOnlyPolicyEngine(config).resolve(request.operation, request.args);
  if (resolved.resourceId !== request.resourceId) {
    throw new OpsHavenError("POLICY_DENIED", "Read-only envelope and operation resource IDs do not match.");
  }
  return {
    version: 1,
    requestId: request.requestId,
    operation: resolved.operation,
    resourceId: resolved.resourceId,
    args: resolved.args,
    limits: resolved.limits,
  };
}
