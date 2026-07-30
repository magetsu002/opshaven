import { canonicalize } from "./canonical.js";
import type { OpsHavenConfig, Resource, ResourceKind } from "./config.js";
import { OpsHavenError } from "./errors.js";

export type OperationName =
  | "get_host_summary"
  | "get_deployed_commit"
  | "get_service_status"
  | "get_container_status"
  | "get_runtime_config_status"
  | "get_reverse_proxy_summary"
  | "get_firewall_summary"
  | "run_health_probe"
  | "get_redacted_logs"
  | "get_monitoring_status"
  | "get_backup_status"
  | "get_restore_readiness"
  | "restart_service"
  | "deploy_commit"
  | "rollback_deployment";

export interface ResolvedOperation {
  operation: OperationName;
  resourceId: string;
  hostId: string;
  args: Readonly<Record<string, string | number | boolean>>;
  expectedState: string;
  policyVersion: string;
  mutation: boolean;
  dryRun: boolean;
  limits: { timeoutMs: number; maxBytes: number; maxLines: number };
}

interface Definition { kinds: ResourceKind[]; mutation: boolean; allowedArgs: readonly string[] }
const DEFINITIONS: Record<OperationName, Definition> = {
  get_host_summary: { kinds: ["host"], mutation: false, allowedArgs: ["resourceId"] },
  get_deployed_commit: { kinds: ["deployment"], mutation: false, allowedArgs: ["resourceId"] },
  get_service_status: { kinds: ["service"], mutation: false, allowedArgs: ["resourceId"] },
  get_container_status: { kinds: ["container"], mutation: false, allowedArgs: ["resourceId"] },
  get_runtime_config_status: { kinds: ["application"], mutation: false, allowedArgs: ["resourceId"] },
  get_reverse_proxy_summary: { kinds: ["proxy"], mutation: false, allowedArgs: ["resourceId"] },
  get_firewall_summary: { kinds: ["host"], mutation: false, allowedArgs: ["resourceId"] },
  run_health_probe: { kinds: ["probe"], mutation: false, allowedArgs: ["resourceId"] },
  get_redacted_logs: { kinds: ["service", "container"], mutation: false, allowedArgs: ["resourceId", "lines", "sinceMinutes"] },
  get_monitoring_status: { kinds: ["monitoring"], mutation: false, allowedArgs: ["resourceId"] },
  get_backup_status: { kinds: ["backup"], mutation: false, allowedArgs: ["resourceId"] },
  get_restore_readiness: { kinds: ["backup"], mutation: false, allowedArgs: ["resourceId"] },
  restart_service: { kinds: ["service"], mutation: true, allowedArgs: ["resourceId", "dryRun"] },
  deploy_commit: { kinds: ["deployment"], mutation: true, allowedArgs: ["resourceId", "commit", "expectedCurrentCommit", "dryRun"] },
  rollback_deployment: { kinds: ["deployment"], mutation: true, allowedArgs: ["resourceId", "releaseId", "dryRun"] },
};

function objectArgs(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new OpsHavenError("INVALID_ARGUMENTS", "Tool arguments must be an object.");
  return input as Record<string, unknown>;
}
function boundedInteger(value: unknown, fallback: number, min: number, max: number, label: string): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) throw new OpsHavenError("INVALID_ARGUMENTS", `${label} is outside its allowed range.`);
  return value as number;
}
function booleanArg(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new OpsHavenError("INVALID_ARGUMENTS", `${label} must be boolean.`);
  return value;
}
function stringArg(value: unknown, pattern: RegExp, label: string, optional = false): string | undefined {
  if (value === undefined && optional) return undefined;
  if (typeof value !== "string" || !pattern.test(value)) throw new OpsHavenError("INVALID_ARGUMENTS", `${label} is invalid.`);
  return value;
}
function resolveHostId(resource: Resource): string { return resource.kind === "host" ? resource.id : resource.hostId; }

export class PolicyEngine {
  constructor(private readonly config: OpsHavenConfig) {}

  resolve(operationInput: string, input: unknown, expectedState = "unresolved"): ResolvedOperation {
    if (!(operationInput in DEFINITIONS)) throw new OpsHavenError("UNKNOWN_OPERATION", "Unknown operation.");
    const operation = operationInput as OperationName;
    const definition = DEFINITIONS[operation];
    const args = objectArgs(input);
    const unknown = Object.keys(args).filter((key) => !definition.allowedArgs.includes(key));
    if (unknown.length) throw new OpsHavenError("INVALID_ARGUMENTS", "Unknown operation arguments.", false, { fields: unknown.sort() });
    const resourceId = stringArg(args.resourceId, /^[a-z][a-z0-9._-]{0,63}$/, "resourceId") as string;
    const resource = this.config.resources.get(resourceId);
    if (!resource) throw new OpsHavenError("UNKNOWN_RESOURCE", "Unknown resource.");
    if (!definition.kinds.includes(resource.kind)) throw new OpsHavenError("POLICY_DENIED", "Operation is not allowed for this resource kind.");
    const normalized: Record<string, string | number | boolean> = { resourceId };
    if (operation === "get_redacted_logs") {
      normalized.lines = boundedInteger(args.lines, 100, 1, Math.min(500, this.config.limits.maxLines), "lines");
      normalized.sinceMinutes = boundedInteger(args.sinceMinutes, 60, 1, 1440, "sinceMinutes");
    }
    if (operation === "restart_service") normalized.dryRun = booleanArg(args.dryRun, false, "dryRun");
    if (operation === "deploy_commit") {
      normalized.commit = stringArg(args.commit, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i, "commit") as string;
      const expected = stringArg(args.expectedCurrentCommit, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i, "expectedCurrentCommit", true);
      if (expected) normalized.expectedCurrentCommit = expected;
      normalized.dryRun = booleanArg(args.dryRun, false, "dryRun");
    }
    if (operation === "rollback_deployment") {
      normalized.releaseId = stringArg(args.releaseId, /^[a-zA-Z0-9._-]{1,128}$/, "releaseId") as string;
      normalized.dryRun = booleanArg(args.dryRun, false, "dryRun");
    }
    const dryRun = normalized.dryRun === true;
    return Object.freeze({ operation, resourceId, hostId: resolveHostId(resource), args: Object.freeze(normalized), expectedState, policyVersion: this.config.policyVersion, mutation: definition.mutation, dryRun, limits: { ...this.config.limits } });
  }

  canonical(operation: ResolvedOperation): string { return canonicalize(operation); }
}
