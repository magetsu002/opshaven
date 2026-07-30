import type { DispatcherHandlers } from "./dispatcher.js";
import {
  assertArgs,
  assertTarget,
  DEFAULT_RUNTIME,
  findResource,
  fixedCommand,
  type HandlerRuntime
} from "./runtime.js";

export type RecoveryRuntime = HandlerRuntime & Readonly<{ now: () => number }>;

const DEFAULT_RECOVERY_RUNTIME: RecoveryRuntime = Object.freeze({
  ...DEFAULT_RUNTIME,
  now: () => Date.now()
});

function parseStat(text: string): { modifiedEpochSeconds: number; sizeBytes: number } {
  const [modified, size] = text.split("|");
  const modifiedEpochSeconds = Number(modified);
  const sizeBytes = Number(size);
  if (!Number.isFinite(modifiedEpochSeconds) || !Number.isFinite(sizeBytes)) {
    throw new Error("stat returned malformed evidence");
  }
  return { modifiedEpochSeconds, sizeBytes };
}

async function statEvidence(
  runtime: RecoveryRuntime,
  request: Parameters<NonNullable<DispatcherHandlers["get_backup_status"]>>[0],
  path: string
): Promise<{ exists: boolean; modifiedEpochSeconds: number | null; sizeBytes: number | null }> {
  const result = await fixedCommand(runtime, request, "/usr/bin/stat", ["--format=%Y|%s", "--", path], {
    allowExitCodes: [0, 1]
  });
  if (result.exitCode !== 0) return { exists: false, modifiedEpochSeconds: null, sizeBytes: null };
  return { exists: true, ...parseStat(result.stdout) };
}

export function createRecoveryHandlers(runtime: RecoveryRuntime = DEFAULT_RECOVERY_RUNTIME): DispatcherHandlers {
  return {
    get_monitoring_status: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["monitoringId"]);
      const monitor = findResource(config.monitoring, request.args.monitoringId, dispatcherHostId, "monitoring");
      assertTarget(request, monitor.id);
      const services: Array<{ serviceId: string; state: string; healthy: boolean }> = [];
      for (const serviceId of monitor.serviceIds) {
        const service = findResource(config.services, serviceId, dispatcherHostId, "service");
        const status = await fixedCommand(runtime, request, "/usr/bin/systemctl", ["is-active", service.unit], {
          allowExitCodes: [0, 3, 4]
        });
        services.push({ serviceId: service.id, state: status.stdout || "unknown", healthy: status.exitCode === 0 });
      }
      return {
        monitoringId: monitor.id,
        healthy: services.every((entry) => entry.healthy),
        services
      };
    },

    get_backup_status: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["backupId"]);
      const backup = findResource(config.backups, request.args.backupId, dispatcherHostId, "backup");
      assertTarget(request, backup.id);
      const evidence = await statEvidence(runtime, request, backup.evidencePath);
      const ageSeconds = evidence.modifiedEpochSeconds === null
        ? null
        : Math.max(0, Math.floor(runtime.now() / 1000 - evidence.modifiedEpochSeconds));
      return {
        backupId: backup.id,
        provider: backup.provider,
        evidenceExists: evidence.exists,
        evidenceSizeBytes: evidence.sizeBytes,
        ageSeconds,
        maximumAgeSeconds: backup.maximumAgeSeconds,
        fresh: ageSeconds !== null && ageSeconds <= backup.maximumAgeSeconds,
        evidenceContentExposed: false
      };
    },

    get_restore_readiness: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["backupId"]);
      const backup = findResource(config.backups, request.args.backupId, dispatcherHostId, "backup");
      assertTarget(request, backup.id);
      const evidence = await statEvidence(runtime, request, backup.evidencePath);
      const procedure = await statEvidence(runtime, request, backup.restoreProcedurePath);
      const ageSeconds = evidence.modifiedEpochSeconds === null
        ? null
        : Math.max(0, Math.floor(runtime.now() / 1000 - evidence.modifiedEpochSeconds));
      const fresh = ageSeconds !== null && ageSeconds <= backup.maximumAgeSeconds;
      return {
        backupId: backup.id,
        backupEvidencePresent: evidence.exists && (evidence.sizeBytes ?? 0) > 0,
        restoreProcedurePresent: procedure.exists && (procedure.sizeBytes ?? 0) > 0,
        backupFresh: fresh,
        ready: evidence.exists && procedure.exists && fresh,
        databaseMigrationsAutomaticallyReversed: false,
        evidenceContentExposed: false
      };
    }
  };
}
