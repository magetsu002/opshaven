import path from "node:path";
import type {
  ApplicationResource,
  BackupResource,
  DeploymentResource,
  MonitoringResource,
  OpsHavenConfig,
  ProxyResource,
  Resource,
  ServiceResource,
} from "../config.js";
import { OpsHavenError } from "../errors.js";
import { sanitizeOutput } from "../redaction.js";
import { readDeploymentState } from "./deployment-state.js";
import { parseUfwSummary } from "./firewall-summary.js";
import { runProbe } from "./probe.js";
import type { ReadOnlyRemoteRequest } from "./read-only-protocol.js";
import type { CommandRunner } from "./runner.js";
import { requireSuccess } from "./runner.js";
import { parseEnvironmentPresence, readTrustedTextFile } from "./safe-files.js";

export interface ReadOnlyHandlerContext {
  config: OpsHavenConfig;
  runner: CommandRunner;
}

const SYSTEMCTL = "/usr/bin/systemctl";
const JOURNALCTL = "/usr/bin/journalctl";
const UFW = "/usr/sbin/ufw";

function options(request: ReadOnlyRemoteRequest): { timeoutMs: number; maxBytes: number; maxLines: number } {
  return {
    timeoutMs: request.limits.timeoutMs,
    maxBytes: request.limits.maxBytes,
    maxLines: request.limits.maxLines,
  };
}

function resource<T extends Resource["kind"]>(
  context: ReadOnlyHandlerContext,
  request: ReadOnlyRemoteRequest,
  kind: T,
): Extract<Resource, { kind: T }> {
  const found = context.config.resources.get(request.resourceId);
  if (!found || found.kind !== kind) {
    throw new OpsHavenError("UNKNOWN_RESOURCE", "Unknown or incompatible read-only resource.");
  }
  return found as Extract<Resource, { kind: T }>;
}

async function serviceStatus(
  context: ReadOnlyHandlerContext,
  request: ReadOnlyRemoteRequest,
  target: ServiceResource,
): Promise<Record<string, unknown>> {
  const output = await requireSuccess(
    context.runner,
    SYSTEMCTL,
    [
      "show",
      target.unit,
      "--no-pager",
      "--property=Id,LoadState,ActiveState,SubState,MainPID,ExecMainStatus,ActiveEnterTimestamp",
    ],
    options(request),
  );
  const values = Object.fromEntries(
    output
      .split("\n")
      .map((line) => line.split("=", 2))
      .filter((pair) => pair.length === 2),
  );
  return {
    unit: target.unit,
    loadState: values.LoadState ?? "unknown",
    activeState: values.ActiveState ?? "unknown",
    subState: values.SubState ?? "unknown",
    mainPid: Number(values.MainPID ?? 0),
    exitStatus: Number(values.ExecMainStatus ?? 0),
    activeSince: values.ActiveEnterTimestamp ?? null,
  };
}

async function runtimeConfig(
  target: ApplicationResource,
  request: ReadOnlyRemoteRequest,
): Promise<Record<string, unknown>> {
  if (!target.environmentFile) {
    return {
      keys: Object.fromEntries(target.runtimeConfigKeys.map((key) => [key, { present: false }])),
      sourceConfigured: false,
    };
  }
  const text = await readTrustedTextFile(target.environmentFile, Math.min(request.limits.maxBytes, 262144));
  return {
    keys: parseEnvironmentPresence(text, target.runtimeConfigKeys),
    sourceConfigured: true,
    sourceType: "trusted_environment_file",
  };
}

async function deployedCommit(
  context: ReadOnlyHandlerContext,
  request: ReadOnlyRemoteRequest,
  target: DeploymentResource,
): Promise<Record<string, unknown>> {
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

async function proxySummary(
  context: ReadOnlyHandlerContext,
  request: ReadOnlyRemoteRequest,
  target: ProxyResource,
): Promise<Record<string, unknown>> {
  const service = context.config.resources.get(target.serviceId);
  if (!service || service.kind !== "service") {
    throw new OpsHavenError("CONFIG_INVALID", "Proxy references an invalid service.");
  }
  return {
    provider: target.provider,
    publicNames: target.publicNames.slice(0, 64),
    publicNameCount: target.publicNames.length,
    service: await serviceStatus(context, request, service),
  };
}

async function serviceLogs(
  context: ReadOnlyHandlerContext,
  request: ReadOnlyRemoteRequest,
  target: ServiceResource,
): Promise<Record<string, unknown>> {
  const lines = Number(request.args.lines);
  const since = Number(request.args.sinceMinutes);
  const raw = await requireSuccess(
    context.runner,
    JOURNALCTL,
    [
      "--unit",
      target.unit,
      "--no-pager",
      "--output=short-iso",
      "--lines",
      String(lines),
      "--since",
      `${since} minutes ago`,
    ],
    options(request),
  );
  const safe = sanitizeOutput(raw, request.limits, context.config.secretFingerprints);
  return {
    text: safe.text,
    lineCount: safe.lineCount,
    byteCount: safe.byteCount,
    redactions: safe.redactions,
    truncated: safe.truncated,
  };
}

async function monitoring(
  context: ReadOnlyHandlerContext,
  request: ReadOnlyRemoteRequest,
  target: MonitoringResource,
): Promise<Record<string, unknown>> {
  const services: Record<string, unknown> = {};
  for (const id of target.serviceIds) {
    const item = context.config.resources.get(id);
    if (!item || item.kind !== "service") {
      throw new OpsHavenError("CONFIG_INVALID", "Monitoring references an invalid service.");
    }
    services[id] = await serviceStatus(context, request, item);
  }
  const probes: Record<string, unknown> = {};
  for (const id of target.probeIds) {
    const item = context.config.resources.get(id);
    if (!item || item.kind !== "probe") {
      throw new OpsHavenError("CONFIG_INVALID", "Monitoring references an invalid probe.");
    }
    probes[id] = await runProbe(item);
  }
  return { services, probes };
}

interface BackupStatusFile {
  lastBackupAt?: unknown;
  lastRestoreTestAt?: unknown;
  backupId?: unknown;
  verified?: unknown;
  bytes?: unknown;
}

async function backup(
  target: BackupResource,
  request: ReadOnlyRemoteRequest,
  restore: boolean,
): Promise<Record<string, unknown>> {
  const parsed = JSON.parse(
    await readTrustedTextFile(target.statusFile, Math.min(request.limits.maxBytes, 65536)),
  ) as BackupStatusFile;
  const lastBackupAt = typeof parsed.lastBackupAt === "string" ? parsed.lastBackupAt : null;
  const lastRestoreTestAt = typeof parsed.lastRestoreTestAt === "string" ? parsed.lastRestoreTestAt : null;
  const ageHours = lastBackupAt ? (Date.now() - Date.parse(lastBackupAt)) / 3600000 : null;
  if (restore) {
    return {
      ready: parsed.verified === true && !!lastRestoreTestAt,
      lastRestoreTestAt,
      migrationWarning: "Database migration reversal is never automatic.",
    };
  }
  return {
    backupId: typeof parsed.backupId === "string" ? parsed.backupId : null,
    lastBackupAt,
    ageHours,
    fresh: ageHours !== null && ageHours <= target.maximumAgeHours,
    verified: parsed.verified === true,
    bytes: typeof parsed.bytes === "number" ? parsed.bytes : null,
  };
}

export async function handleReadOnlyInspection(
  context: ReadOnlyHandlerContext,
  request: ReadOnlyRemoteRequest,
): Promise<Record<string, unknown>> {
  switch (request.operation) {
    case "get_host_summary": {
      resource(context, request, "host");
      const uname = await requireSuccess(context.runner, "/usr/bin/uname", ["-srmo"], options(request));
      const uptime = await requireSuccess(context.runner, "/usr/bin/uptime", ["-p"], options(request));
      const disk = await requireSuccess(context.runner, "/usr/bin/df", ["-P", "/"], options(request));
      return { uname, uptime, rootFilesystem: disk.split("\n").at(-1) ?? "" };
    }
    case "get_deployed_commit":
      return await deployedCommit(context, request, resource(context, request, "deployment"));
    case "get_service_status":
      return await serviceStatus(context, request, resource(context, request, "service"));
    case "get_runtime_config_status":
      return await runtimeConfig(resource(context, request, "application"), request);
    case "get_reverse_proxy_summary":
      return await proxySummary(context, request, resource(context, request, "proxy"));
    case "get_firewall_summary": {
      resource(context, request, "host");
      const raw = await requireSuccess(context.runner, UFW, ["status", "numbered"], options(request));
      return parseUfwSummary(raw, request.limits, context.config.secretFingerprints);
    }
    case "run_health_probe":
      return { ...(await runProbe(resource(context, request, "probe"))) };
    case "get_redacted_logs":
      return await serviceLogs(context, request, resource(context, request, "service"));
    case "get_monitoring_status":
      return await monitoring(context, request, resource(context, request, "monitoring"));
    case "get_backup_status":
      return await backup(resource(context, request, "backup"), request, false);
    case "get_restore_readiness":
      return await backup(resource(context, request, "backup"), request, true);
  }
}
