import type { OpsHavenConfig, Resource, ResourceKind } from "../config.js";
import { OpsHavenError } from "../errors.js";

export const READ_ONLY_OPERATIONS = [
  "get_host_summary",
  "get_deployed_commit",
  "get_service_status",
  "get_runtime_config_status",
  "get_reverse_proxy_summary",
  "get_firewall_summary",
  "run_health_probe",
  "get_redacted_logs",
  "get_monitoring_status",
  "get_backup_status",
  "get_restore_readiness",
] as const;

export type ReadOnlyOperationName = (typeof READ_ONLY_OPERATIONS)[number];

export interface ResolvedReadOnlyOperation {
  operation: ReadOnlyOperationName;
  resourceId: string;
  hostId: string;
  args: Readonly<Record<string, string | number | boolean>>;
  limits: { timeoutMs: number; maxBytes: number; maxLines: number };
}

interface Definition {
  kinds: ResourceKind[];
  allowedArgs: readonly string[];
}

const DEFINITIONS: Record<ReadOnlyOperationName, Definition> = {
  get_host_summary: { kinds: ["host"], allowedArgs: ["resourceId"] },
  get_deployed_commit: { kinds: ["deployment"], allowedArgs: ["resourceId"] },
  get_service_status: { kinds: ["service"], allowedArgs: ["resourceId"] },
  get_runtime_config_status: { kinds: ["application"], allowedArgs: ["resourceId"] },
  get_reverse_proxy_summary: { kinds: ["proxy"], allowedArgs: ["resourceId"] },
  get_firewall_summary: { kinds: ["host"], allowedArgs: ["resourceId"] },
  run_health_probe: { kinds: ["probe"], allowedArgs: ["resourceId"] },
  get_redacted_logs: { kinds: ["service"], allowedArgs: ["resourceId", "lines", "sinceMinutes"] },
  get_monitoring_status: { kinds: ["monitoring"], allowedArgs: ["resourceId"] },
  get_backup_status: { kinds: ["backup"], allowedArgs: ["resourceId"] },
  get_restore_readiness: { kinds: ["backup"], allowedArgs: ["resourceId"] },
};

function objectArgs(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new OpsHavenError("INVALID_ARGUMENTS", "Tool arguments must be an object.");
  }
  return input as Record<string, unknown>;
}

function boundedInteger(value: unknown, fallback: number, min: number, max: number, label: string): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    throw new OpsHavenError("INVALID_ARGUMENTS", `${label} is outside its allowed range.`);
  }
  return value as number;
}

function resourceId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z][a-z0-9._-]{0,63}$/.test(value)) {
    throw new OpsHavenError("INVALID_ARGUMENTS", "resourceId is invalid.");
  }
  return value;
}

function resolveHostId(resource: Resource): string {
  return resource.kind === "host" ? resource.id : resource.hostId;
}

export class ReadOnlyPolicyEngine {
  constructor(private readonly config: OpsHavenConfig) {}

  resolve(operationInput: string, input: unknown): ResolvedReadOnlyOperation {
    if (!Object.prototype.hasOwnProperty.call(DEFINITIONS, operationInput)) {
      throw new OpsHavenError("UNKNOWN_OPERATION", "Unknown read-only operation.");
    }
    const operation = operationInput as ReadOnlyOperationName;
    const definition = DEFINITIONS[operation];
    const inputArgs = objectArgs(input);
    const unknown = Object.keys(inputArgs).filter((key) => !definition.allowedArgs.includes(key));
    if (unknown.length > 0) {
      throw new OpsHavenError("INVALID_ARGUMENTS", "Unknown read-only operation arguments.", false, { fields: unknown.sort() });
    }
    const id = resourceId(inputArgs.resourceId);
    const target = this.config.resources.get(id);
    if (!target) throw new OpsHavenError("UNKNOWN_RESOURCE", "Unknown resource.");
    if (!definition.kinds.includes(target.kind)) {
      throw new OpsHavenError("POLICY_DENIED", "Read-only operation is unavailable for this resource kind.");
    }
    const normalized: Record<string, string | number | boolean> = { resourceId: id };
    if (operation === "get_redacted_logs") {
      normalized.lines = boundedInteger(inputArgs.lines, 100, 1, Math.min(500, this.config.limits.maxLines), "lines");
      normalized.sinceMinutes = boundedInteger(inputArgs.sinceMinutes, 60, 1, 1440, "sinceMinutes");
    }
    return Object.freeze({
      operation,
      resourceId: id,
      hostId: resolveHostId(target),
      args: Object.freeze(normalized),
      limits: { ...this.config.limits },
    });
  }
}
