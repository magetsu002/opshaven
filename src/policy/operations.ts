import { randomUUID } from "node:crypto";
import type {
  BackupConfig,
  ContainerConfig,
  DeploymentConfig,
  HostConfig,
  MonitoringConfig,
  OpsHavenConfig,
  ProbeConfig,
  ProxyConfig,
  ServiceConfig
} from "../config/schema.js";
import { OpsHavenError } from "../core/errors.js";
import type { OutputBounds } from "../core/types.js";
import type { JsonValue } from "../security/canonical.js";

export const OPERATION_NAMES = [
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
  "rollback_deployment"
] as const;

export type OperationName = (typeof OPERATION_NAMES)[number];
export type OperationKind = "read" | "mutation";

export type ResolvedOperation = Readonly<{
  requestId: string;
  operation: OperationName;
  kind: OperationKind;
  target: string;
  hostId: string;
  args: { readonly [key: string]: JsonValue };
  expectedState: { readonly [key: string]: JsonValue };
  policyVersion: string;
  timeoutMs: number;
  output: OutputBounds;
  dryRun: boolean;
  requiresApproval: boolean;
}>;

type ObjectValue = Record<string, unknown>;

function object(value: unknown, context: string): ObjectValue {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpsHavenError("POLICY_DENIED", `${context} must be an object`);
  }
  return value as ObjectValue;
}

function exact(value: ObjectValue, allowed: readonly string[], context: string): void {
  const fields = Object.keys(value).filter((field) => !allowed.includes(field));
  if (fields.length > 0) throw new OpsHavenError("POLICY_DENIED", `${context} contains unknown fields`, { fields });
}

function string(value: unknown, context: string, pattern?: RegExp): string {
  if (typeof value !== "string" || value.length === 0 || (pattern !== undefined && !pattern.test(value))) {
    throw new OpsHavenError("POLICY_DENIED", `${context} is invalid`);
  }
  return value;
}

function boolean(value: unknown, context: string): boolean {
  if (typeof value !== "boolean") throw new OpsHavenError("POLICY_DENIED", `${context} must be boolean`);
  return value;
}

function optionalBoolean(value: unknown, context: string, fallback: boolean): boolean {
  return value === undefined ? fallback : boolean(value, context);
}

function optionalInteger(value: unknown, context: string, fallback: number, minimum: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new OpsHavenError("POLICY_DENIED", `${context} must be an integer from ${minimum} to ${maximum}`);
  }
  return value as number;
}

function find<T extends { id: string }>(items: readonly T[], resourceId: string, type: string): T {
  const resource = items.find((item) => item.id === resourceId);
  if (resource === undefined) {
    throw new OpsHavenError("RESOURCE_NOT_FOUND", `Unknown ${type} logical resource`, { resourceId });
  }
  return resource;
}

function host(config: OpsHavenConfig, hostId: string): HostConfig {
  return find(config.hosts, hostId, "host");
}

function resolved(
  config: OpsHavenConfig,
  operation: OperationName,
  kind: OperationKind,
  target: string,
  hostId: string,
  args: ResolvedOperation["args"],
  expectedState: ResolvedOperation["expectedState"] = {},
  dryRun = false,
  timeoutMs = config.defaults.timeoutMs,
  output = config.defaults.output
): ResolvedOperation {
  host(config, hostId);
  return {
    requestId: randomUUID(),
    operation,
    kind,
    target,
    hostId,
    args,
    expectedState,
    policyVersion: config.policyVersion,
    timeoutMs,
    output,
    dryRun,
    requiresApproval: kind === "mutation" && !dryRun
  };
}

function oneId(value: unknown, field: string): { input: ObjectValue; id: string } {
  const input = object(value, "arguments");
  exact(input, [field], "arguments");
  return { input, id: string(input[field], `arguments.${field}`, /^[a-z][a-z0-9_-]{1,63}$/) };
}

function serviceOperation(config: OpsHavenConfig, name: OperationName, input: unknown): ResolvedOperation {
  const { id } = oneId(input, "serviceId");
  const service = find<ServiceConfig>(config.services, id, "service");
  return resolved(config, name, "read", service.id, service.hostId, { serviceId: service.id });
}

function deploymentOperation(config: OpsHavenConfig, name: OperationName, input: unknown): ResolvedOperation {
  const { id } = oneId(input, "deploymentId");
  const deployment = find<DeploymentConfig>(config.deployments, id, "deployment");
  return resolved(config, name, "read", deployment.id, deployment.hostId, { deploymentId: deployment.id });
}

function resourceOperation<T extends { id: string; hostId: string }>(
  config: OpsHavenConfig,
  name: OperationName,
  input: unknown,
  field: string,
  type: string,
  items: readonly T[]
): ResolvedOperation {
  const { id } = oneId(input, field);
  const resource = find(items, id, type);
  return resolved(config, name, "read", resource.id, resource.hostId, { [field]: resource.id });
}

function resolveLogs(config: OpsHavenConfig, value: unknown): ResolvedOperation {
  const input = object(value, "arguments");
  exact(input, ["serviceId", "lines", "window"], "arguments");
  const serviceId = string(input.serviceId, "arguments.serviceId", /^[a-z][a-z0-9_-]{1,63}$/);
  const service = find(config.services, serviceId, "service");
  const lines = optionalInteger(input.lines, "arguments.lines", 100, 1, 500);
  const window = input.window === undefined ? "1h" : string(input.window, "arguments.window", /^(15m|1h|24h)$/);
  return resolved(
    config,
    "get_redacted_logs",
    "read",
    service.id,
    service.hostId,
    { serviceId: service.id, lines, window },
    {},
    false,
    config.defaults.timeoutMs,
    { maxBytes: Math.min(config.defaults.output.maxBytes, 131_072), maxLines: lines }
  );
}

function resolveRestart(config: OpsHavenConfig, value: unknown): ResolvedOperation {
  const input = object(value, "arguments");
  exact(input, ["serviceId", "expectedActiveState", "dryRun"], "arguments");
  const serviceId = string(input.serviceId, "arguments.serviceId", /^[a-z][a-z0-9_-]{1,63}$/);
  const service = find(config.services, serviceId, "service");
  if (!service.restartAllowed) {
    throw new OpsHavenError("POLICY_DENIED", "Restart is not allowed for this configured service", { serviceId });
  }
  const expectedActiveState = string(input.expectedActiveState, "arguments.expectedActiveState", /^(active|inactive|failed)$/);
  const dryRun = optionalBoolean(input.dryRun, "arguments.dryRun", false);
  return resolved(
    config,
    "restart_service",
    "mutation",
    service.id,
    service.hostId,
    { serviceId: service.id },
    { activeState: expectedActiveState },
    dryRun
  );
}

function resolveDeploy(config: OpsHavenConfig, value: unknown): ResolvedOperation {
  const input = object(value, "arguments");
  exact(
    input,
    ["deploymentId", "commit", "expectedCurrentCommit", "acknowledgeMigrationRisk", "dryRun"],
    "arguments"
  );
  const deploymentId = string(input.deploymentId, "arguments.deploymentId", /^[a-z][a-z0-9_-]{1,63}$/);
  const deployment = find(config.deployments, deploymentId, "deployment");
  const commit = string(input.commit, "arguments.commit", /^[a-f0-9]{40}$/);
  const expectedCurrentCommit = string(input.expectedCurrentCommit, "arguments.expectedCurrentCommit", /^[a-f0-9]{40}$/);
  const acknowledgeMigrationRisk = optionalBoolean(
    input.acknowledgeMigrationRisk,
    "arguments.acknowledgeMigrationRisk",
    false
  );
  if (deployment.migrationRisk === "manual-review" && !acknowledgeMigrationRisk) {
    throw new OpsHavenError("POLICY_DENIED", "Deployment requires explicit migration-risk acknowledgement");
  }
  const dryRun = optionalBoolean(input.dryRun, "arguments.dryRun", false);
  return resolved(
    config,
    "deploy_commit",
    "mutation",
    deployment.id,
    deployment.hostId,
    { deploymentId: deployment.id, commit, acknowledgeMigrationRisk },
    { currentCommit: expectedCurrentCommit },
    dryRun,
    1_800_000,
    { maxBytes: config.defaults.output.maxBytes, maxLines: Math.min(config.defaults.output.maxLines, 2_000) }
  );
}

function resolveRollback(config: OpsHavenConfig, value: unknown): ResolvedOperation {
  const input = object(value, "arguments");
  exact(input, ["deploymentId", "releaseCommit", "expectedCurrentCommit", "dryRun"], "arguments");
  const deploymentId = string(input.deploymentId, "arguments.deploymentId", /^[a-z][a-z0-9_-]{1,63}$/);
  const deployment = find(config.deployments, deploymentId, "deployment");
  const releaseCommit = string(input.releaseCommit, "arguments.releaseCommit", /^[a-f0-9]{40}$/);
  const expectedCurrentCommit = string(input.expectedCurrentCommit, "arguments.expectedCurrentCommit", /^[a-f0-9]{40}$/);
  const dryRun = optionalBoolean(input.dryRun, "arguments.dryRun", false);
  return resolved(
    config,
    "rollback_deployment",
    "mutation",
    deployment.id,
    deployment.hostId,
    { deploymentId: deployment.id, releaseCommit },
    { currentCommit: expectedCurrentCommit },
    dryRun,
    300_000
  );
}

export function isOperationName(value: string): value is OperationName {
  return (OPERATION_NAMES as readonly string[]).includes(value);
}

export function resolveOperation(config: OpsHavenConfig, operation: string, input: unknown): ResolvedOperation {
  if (!isOperationName(operation)) throw new OpsHavenError("POLICY_DENIED", "Unknown operation", { operation });
  switch (operation) {
    case "get_host_summary": {
      const { id } = oneId(input, "hostId");
      return resolved(config, operation, "read", id, host(config, id).id, { hostId: id });
    }
    case "get_deployed_commit":
      return deploymentOperation(config, operation, input);
    case "get_service_status":
    case "get_runtime_config_status":
      return serviceOperation(config, operation, input);
    case "get_container_status":
      return resourceOperation<ContainerConfig>(config, operation, input, "containerId", "container", config.containers);
    case "get_reverse_proxy_summary":
      return resourceOperation<ProxyConfig>(config, operation, input, "proxyId", "proxy", config.proxies);
    case "get_firewall_summary": {
      const { id } = oneId(input, "hostId");
      return resolved(config, operation, "read", id, host(config, id).id, { hostId: id });
    }
    case "run_health_probe":
      return resourceOperation<ProbeConfig>(config, operation, input, "probeId", "probe", config.probes);
    case "get_redacted_logs":
      return resolveLogs(config, input);
    case "get_monitoring_status":
      return resourceOperation<MonitoringConfig>(
        config,
        operation,
        input,
        "monitoringId",
        "monitoring configuration",
        config.monitoring
      );
    case "get_backup_status":
    case "get_restore_readiness":
      return resourceOperation<BackupConfig>(config, operation, input, "backupId", "backup", config.backups);
    case "restart_service":
      return resolveRestart(config, input);
    case "deploy_commit":
      return resolveDeploy(config, input);
    case "rollback_deployment":
      return resolveRollback(config, input);
  }
}
