import path from "node:path";
import type { ApplicationResource, BackupResource, ContainerResource, DeploymentResource, MonitoringResource, OpsHavenConfig, ProbeResource, ProxyResource, Resource, ServiceResource } from "../config.js";
import { OpsHavenError } from "../errors.js";
import type { OperationName } from "../policy.js";
import { sanitizeOutput } from "../redaction.js";
import { readDeploymentState } from "./deployment-state.js";
import type { RemoteRequest } from "./protocol.js";
import { runProbe } from "./probe.js";
import type { CommandRunner } from "./runner.js";
import { requireSuccess } from "./runner.js";
import { parseEnvironmentPresence, readTrustedTextFile } from "./safe-files.js";

export interface HandlerContext { config: OpsHavenConfig; runner: CommandRunner }
const SYSTEMCTL = "/usr/bin/systemctl";
const JOURNALCTL = "/usr/bin/journalctl";
const DOCKER = "/usr/bin/docker";
const UFW = "/usr/sbin/ufw";

function options(request: RemoteRequest) { return { timeoutMs: request.limits.timeoutMs, maxBytes: request.limits.maxBytes, maxLines: request.limits.maxLines }; }
function resource<T extends Resource["kind"]>(context: HandlerContext, request: RemoteRequest, kind: T): Extract<Resource, { kind: T }> {
  const found = context.config.resources.get(request.resourceId);
  if (!found || found.kind !== kind) throw new OpsHavenError("UNKNOWN_RESOURCE", "Unknown or incompatible remote resource.");
  return found as Extract<Resource, { kind: T }>;
}
async function serviceStatus(context: HandlerContext, request: RemoteRequest, target: ServiceResource): Promise<Record<string, unknown>> {
  const output = await requireSuccess(context.runner, SYSTEMCTL, ["show", target.unit, "--no-pager", "--property=Id,LoadState,ActiveState,SubState,MainPID,ExecMainStatus,ActiveEnterTimestamp"], options(request));
  const values = Object.fromEntries(output.split("\n").map((line) => line.split("=", 2)).filter((pair) => pair.length === 2));
  return { unit: target.unit, loadState: values.LoadState ?? "unknown", activeState: values.ActiveState ?? "unknown", subState: values.SubState ?? "unknown", mainPid: Number(values.MainPID ?? 0), exitStatus: Number(values.ExecMainStatus ?? 0), activeSince: values.ActiveEnterTimestamp ?? null };
}
async function containerStatus(context: HandlerContext, request: RemoteRequest, target: ContainerResource): Promise<Record<string, unknown>> {
  const output = await requireSuccess(context.runner, DOCKER, ["inspect", "--format", "{{json .State}}", target.container], options(request));
  const state = JSON.parse(output) as Record<string, unknown>;
  return { container: target.container, running: state.Running === true, status: typeof state.Status === "string" ? state.Status : "unknown", startedAt: typeof state.StartedAt === "string" ? state.StartedAt : null, exitCode: typeof state.ExitCode === "number" ? state.ExitCode : null, restartCount: typeof state.RestartCount === "number" ? state.RestartCount : null };
}
async function runtimeConfig(target: ApplicationResource, request: RemoteRequest): Promise<Record<string, unknown>> {
  if (!target.environmentFile) return { keys: Object.fromEntries(target.runtimeConfigKeys.map((key) => [key, { present: false }])), sourceConfigured: false };
  const text = await readTrustedTextFile(target.environmentFile, Math.min(request.limits.maxBytes, 262144));
  return { keys: parseEnvironmentPresence(text, target.runtimeConfigKeys), sourceConfigured: true, sourceType: "trusted_environment_file" };
}
async function deployedCommit(context: HandlerContext, request: RemoteRequest, target: DeploymentResource): Promise<Record<string, unknown>> {
  const state = await readDeploymentState(target, context.runner, options(request));
  return {
    commit: state.activeCommit,
    activeCommit: state.activeCommit,
    activeReleaseId: state.activeReleasePath ? path.basename(state.activeReleasePath) : null,
    sourceRepositoryCommit: state.sourceRepositoryCommit,
    dirty: state.sourceRepositoryDirty,
    repositoryId: target.id,
    migrationPolicy: target.migrationPolicy,
  };
}
async function proxySummary(context: HandlerContext, request: RemoteRequest, target: ProxyResource): Promise<Record<string, unknown>> {
  const service = context.config.resources.get(target.serviceId);
  if (!service || service.kind !== "service") throw new OpsHavenError("CONFIG_INVALID", "Proxy references an invalid service.");
  const status = await serviceStatus(context, request, service);
  return { provider: target.provider, publicNames: target.publicNames, service: status };
}
async function logs(context: HandlerContext, request: RemoteRequest, target: ServiceResource | ContainerResource): Promise<Record<string, unknown>> {
  const lines = Number(request.args.lines);
  const since = Number(request.args.sinceMinutes);
  const raw = target.kind === "service"
    ? await requireSuccess(context.runner, JOURNALCTL, ["--unit", target.unit, "--no-pager", "--output=short-iso", "--lines", String(lines), "--since", `${since} minutes ago`], options(request))
    : await requireSuccess(context.runner, DOCKER, ["logs", "--tail", String(lines), "--since", `${since}m`, target.container], options(request));
  const safe = sanitizeOutput(raw, request.limits, context.config.secretFingerprints);
  return { text: safe.text, lineCount: safe.lineCount, byteCount: safe.byteCount, redactions: safe.redactions, truncated: safe.truncated };
}
async function monitoring(context: HandlerContext, request: RemoteRequest, target: MonitoringResource): Promise<Record<string, unknown>> {
  const services: Record<string, unknown> = {};
  for (const id of target.serviceIds) {
    const item = context.config.resources.get(id);
    if (!item || item.kind !== "service") throw new OpsHavenError("CONFIG_INVALID", "Monitoring references an invalid service.");
    services[id] = await serviceStatus(context, request, item);
  }
  const probes: Record<string, unknown> = {};
  for (const id of target.probeIds) {
    const item = context.config.resources.get(id);
    if (!item || item.kind !== "probe") throw new OpsHavenError("CONFIG_INVALID", "Monitoring references an invalid probe.");
    probes[id] = await runProbe(item);
  }
  return { services, probes };
}
interface BackupStatusFile { lastBackupAt?: unknown; lastRestoreTestAt?: unknown; backupId?: unknown; verified?: unknown; bytes?: unknown }
async function backup(target: BackupResource, request: RemoteRequest, restore: boolean): Promise<Record<string, unknown>> {
  const parsed = JSON.parse(await readTrustedTextFile(target.statusFile, Math.min(request.limits.maxBytes, 65536))) as BackupStatusFile;
  const lastBackupAt = typeof parsed.lastBackupAt === "string" ? parsed.lastBackupAt : null;
  const lastRestoreTestAt = typeof parsed.lastRestoreTestAt === "string" ? parsed.lastRestoreTestAt : null;
  const ageHours = lastBackupAt ? (Date.now() - Date.parse(lastBackupAt)) / 3600000 : null;
  if (restore) return { ready: parsed.verified === true && !!lastRestoreTestAt, lastRestoreTestAt, migrationWarning: "Database migration reversal is never automatic." };
  return { backupId: typeof parsed.backupId === "string" ? parsed.backupId : null, lastBackupAt, ageHours, fresh: ageHours !== null && ageHours <= target.maximumAgeHours, verified: parsed.verified === true, bytes: typeof parsed.bytes === "number" ? parsed.bytes : null };
}

export async function handleInspection(context: HandlerContext, request: RemoteRequest): Promise<Record<string, unknown>> {
  const operation = request.operation as OperationName | "get_state_fingerprint";
  switch (operation) {
    case "get_host_summary": {
      resource(context, request, "host");
      const uname = await requireSuccess(context.runner, "/usr/bin/uname", ["-srmo"], options(request));
      const uptime = await requireSuccess(context.runner, "/usr/bin/uptime", ["-p"], options(request));
      const disk = await requireSuccess(context.runner, "/usr/bin/df", ["-P", "/"], options(request));
      return { uname, uptime, rootFilesystem: disk.split("\n").at(-1) ?? "" };
    }
    case "get_deployed_commit": return deployedCommit(context, request, resource(context, request, "deployment"));
    case "get_service_status": return serviceStatus(context, request, resource(context, request, "service"));
    case "get_container_status": return containerStatus(context, request, resource(context, request, "container"));
    case "get_runtime_config_status": return runtimeConfig(resource(context, request, "application"), request);
    case "get_reverse_proxy_summary": return proxySummary(context, request, resource(context, request, "proxy"));
    case "get_firewall_summary": {
      resource(context, request, "host");
      const raw = await requireSuccess(context.runner, UFW, ["status", "numbered"], options(request));
      const safe = sanitizeOutput(raw, request.limits, context.config.secretFingerprints);
      return { provider: "ufw", text: safe.text, redactions: safe.redactions, truncated: safe.truncated };
    }
    case "run_health_probe": return { ...(await runProbe(resource(context, request, "probe"))) };
    case "get_redacted_logs": {
      const target = context.config.resources.get(request.resourceId);
      if (!target || (target.kind !== "service" && target.kind !== "container")) throw new OpsHavenError("UNKNOWN_RESOURCE", "Unknown log resource.");
      return logs(context, request, target);
    }
    case "get_monitoring_status": return monitoring(context, request, resource(context, request, "monitoring"));
    case "get_backup_status": return backup(resource(context, request, "backup"), request, false);
    case "get_restore_readiness": return backup(resource(context, request, "backup"), request, true);
    case "get_state_fingerprint": {
      const target = context.config.resources.get(request.resourceId);
      if (!target) throw new OpsHavenError("UNKNOWN_RESOURCE", "Unknown state resource.");
      if (target.kind === "service") return serviceStatus(context, request, target);
      if (target.kind === "deployment") return deployedCommit(context, request, target);
      throw new OpsHavenError("POLICY_DENIED", "State fingerprint is unavailable for this resource.");
    }
    default: throw new OpsHavenError("UNKNOWN_OPERATION", "Unknown remote inspection operation.");
  }
}
