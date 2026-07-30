import type { OpsHavenConfig } from "../config/schema.js";
import { OpsHavenError } from "../core/errors.js";
import type { JsonValue } from "../security/canonical.js";
import { runProcess, type ProcessRunner } from "../transport/process.js";
import type { DispatcherRequest } from "./protocol.js";

export type HandlerRuntime = Readonly<{
  runner: ProcessRunner;
}>;

export const DEFAULT_RUNTIME: HandlerRuntime = Object.freeze({ runner: runProcess });

export function findResource<T extends { id: string; hostId: string }>(
  items: readonly T[],
  id: JsonValue | undefined,
  dispatcherHostId: string,
  type: string
): T {
  if (typeof id !== "string") throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", `${type} ID must be a string`);
  const resource = items.find((item) => item.id === id);
  if (resource === undefined || resource.hostId !== dispatcherHostId) {
    throw new OpsHavenError("RESOURCE_NOT_FOUND", `Unknown ${type} on this dispatcher`, { resourceId: id });
  }
  return resource;
}

export function assertArgs(request: DispatcherRequest, allowed: readonly string[]): void {
  const fields = Object.keys(request.args).filter((field) => !allowed.includes(field));
  if (fields.length > 0) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Operation arguments contain unknown fields", { fields });
  }
}

export async function fixedCommand(
  runtime: HandlerRuntime,
  request: DispatcherRequest,
  executable: string,
  args: readonly string[],
  options: Readonly<{ allowExitCodes?: readonly number[]; timeoutMs?: number }> = {}
): Promise<Readonly<{ stdout: string; stderr: string; exitCode: number }>> {
  const result = await runtime.runner({
    executable,
    args,
    timeoutMs: Math.min(options.timeoutMs ?? request.limits.timeoutMs, request.limits.timeoutMs),
    output: { maxBytes: request.limits.maxBytes, maxLines: request.limits.maxLines }
  });
  const allowed = options.allowExitCodes ?? [0];
  const stdout = Buffer.from(result.stdout).toString("utf8").trim();
  const stderr = Buffer.from(result.stderr).toString("utf8").trim();
  if (stdout.includes("\0") || stderr.includes("\0")) {
    throw new OpsHavenError("BINARY_OUTPUT_REJECTED", "Fixed command emitted binary output");
  }
  if (!allowed.includes(result.exitCode)) {
    throw new OpsHavenError("OPERATION_FAILED", "Fixed command failed", {
      executable,
      exitCode: result.exitCode,
      stderr: stderr.slice(0, 512)
    });
  }
  return { stdout, stderr, exitCode: result.exitCode };
}

export function assertTarget(request: DispatcherRequest, id: string): void {
  if (request.target !== id) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Request target does not match resolved resource ID");
  }
}

export function requireHost(config: OpsHavenConfig, dispatcherHostId: string): void {
  if (!config.hosts.some((item) => item.id === dispatcherHostId)) {
    throw new OpsHavenError("CONFIG_INVALID", "Dispatcher host ID is not configured");
  }
}
