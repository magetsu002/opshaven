import { OpsHavenError } from "../core/errors.js";
import { isOperationName, type OperationName } from "../policy/operations.js";
import type { JsonValue } from "../security/canonical.js";

export type DispatcherRequest = Readonly<{
  version: 1;
  requestId: string;
  operation: OperationName;
  target: string;
  args: { readonly [key: string]: JsonValue };
  expectedState: { readonly [key: string]: JsonValue };
  dryRun: boolean;
  limits: Readonly<{ timeoutMs: number; maxBytes: number; maxLines: number }>;
}>;

export type DispatcherSuccess = Readonly<{
  version: 1;
  requestId: string;
  ok: true;
  data: JsonValue;
}>;

export type DispatcherFailure = Readonly<{
  version: 1;
  requestId: string;
  ok: false;
  error: Readonly<{
    code: string;
    message: string;
    retryable: boolean;
    details: { readonly [key: string]: JsonValue };
  }>;
}>;

export type DispatcherResponse = DispatcherSuccess | DispatcherFailure;

type JsonObject = Record<string, unknown>;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ID = /^[a-z][a-z0-9_-]{1,63}$/;

function object(value: unknown, context: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", `${context} must be an object`);
  }
  return value as JsonObject;
}

function exact(value: JsonObject, allowed: readonly string[], context: string): void {
  const fields = Object.keys(value).filter((field) => !allowed.includes(field));
  if (fields.length > 0) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", `${context} contains unknown fields`, { fields });
  }
}

function integer(value: unknown, context: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", `${context} is outside the dispatcher hard limit`);
  }
  return value as number;
}

function jsonObject(value: unknown, context: string): { readonly [key: string]: JsonValue } {
  const parsed = object(value, context);
  JSON.stringify(parsed);
  return parsed as { readonly [key: string]: JsonValue };
}

export function parseDispatcherRequest(value: unknown): DispatcherRequest {
  const root = object(value, "request");
  exact(root, ["version", "requestId", "operation", "target", "args", "expectedState", "dryRun", "limits"], "request");
  if (root.version !== 1) throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "request.version must be 1");
  if (typeof root.requestId !== "string" || !UUID.test(root.requestId)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "request.requestId must be a UUID");
  }
  if (typeof root.operation !== "string" || !isOperationName(root.operation)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "request.operation is unknown");
  }
  if (typeof root.target !== "string" || !ID.test(root.target)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "request.target must be a logical ID");
  }
  if (typeof root.dryRun !== "boolean") {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "request.dryRun must be boolean");
  }
  const limits = object(root.limits, "request.limits");
  exact(limits, ["timeoutMs", "maxBytes", "maxLines"], "request.limits");
  return {
    version: 1,
    requestId: root.requestId,
    operation: root.operation,
    target: root.target,
    args: jsonObject(root.args, "request.args"),
    expectedState: jsonObject(root.expectedState, "request.expectedState"),
    dryRun: root.dryRun,
    limits: {
      timeoutMs: integer(limits.timeoutMs, "request.limits.timeoutMs", 100, 1_800_000),
      maxBytes: integer(limits.maxBytes, "request.limits.maxBytes", 256, 1_048_576),
      maxLines: integer(limits.maxLines, "request.limits.maxLines", 1, 10_000)
    }
  };
}
