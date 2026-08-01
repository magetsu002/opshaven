import { randomBytes } from "node:crypto";
import { AuditLog } from "../audit.js";
import { sha256 } from "../canonical.js";
import { loadConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { certifyRemoteBoundary, type RemoteBoundaryReceipt } from "./certify.js";
import type { RemoteSetupConfig } from "./remote.js";
import { rollbackRecordedSynchronization } from "./rollback.js";
import { readInstalledRemoteState, type InstalledRemoteState } from "./state.js";
import { inspectRemoteSynchronizationTransaction, type SynchronizationTransactionInspection } from "./transaction-inspection.js";
import { advanceRemoteSynchronizationTransaction } from "./transaction.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export interface RemoteSetupRepairPlan {
  readonly version: 1;
  readonly action: "restore-previous" | "none" | "clean-reinstall-required";
  readonly transactionId: string | null;
  readonly lastCompletedPhase: string | null;
  readonly desiredGeneration: string | null;
  readonly previousGeneration: string | null;
  readonly rollbackAvailable: boolean;
  readonly evidencePreserved: true;
  readonly changes: readonly string[];
}

export interface RemoteSetupRepairReceipt {
  readonly ok: true;
  readonly action: "restore-previous" | "none";
  readonly transactionId: string | null;
  readonly restoredGenerationIdentity: string | null;
  readonly installedGeneration: number | null;
  readonly boundary: RemoteBoundaryReceipt | null;
  readonly auditEvidenceDigest: string;
  readonly repairedAt: string;
}

function planFromInspection(inspection: SynchronizationTransactionInspection): RemoteSetupRepairPlan {
  const transaction = inspection.transaction;
  if (inspection.status === "absent" || inspection.status === "resolved") {
    return Object.freeze({ version: 1, action: "none", transactionId: transaction?.transactionId ?? null, lastCompletedPhase: inspection.lastCompletedPhase, desiredGeneration: transaction?.desiredGenerationIdentity ?? null, previousGeneration: transaction?.previousGenerationIdentity ?? null, rollbackAvailable: false, evidencePreserved: true, changes: Object.freeze(["No unresolved synchronization transaction requires repair."]) });
  }
  if (inspection.status === "unresolved" && inspection.integrityValid && inspection.hostBindingValid && inspection.rollbackAvailable && transaction?.previousGenerationAvailable) {
    return Object.freeze({
      version: 1,
      action: "restore-previous",
      transactionId: transaction.transactionId,
      lastCompletedPhase: inspection.lastCompletedPhase,
      desiredGeneration: transaction.desiredGenerationIdentity,
      previousGeneration: transaction.previousGenerationIdentity,
      rollbackAvailable: true,
      evidencePreserved: true,
      changes: Object.freeze([
        "Validate the immutable previous-generation snapshot and receipt chain.",
        "Restore only the recorded previous runtime, dispatcher, authorization, declarations, and canonical state.",
        "Download only public and signed verification artifacts required for certification.",
        "Verify the restored boundary and recorded generation identity.",
        "Preserve the failed transaction evidence and append repair audit evidence.",
      ]),
    });
  }
  return Object.freeze({
    version: 1,
    action: "clean-reinstall-required",
    transactionId: transaction?.transactionId ?? null,
    lastCompletedPhase: inspection.lastCompletedPhase,
    desiredGeneration: transaction?.desiredGenerationIdentity ?? null,
    previousGeneration: transaction?.previousGenerationIdentity ?? null,
    rollbackAvailable: false,
    evidencePreserved: true,
    changes: Object.freeze([
      "Preserve the failed transaction and installed-state evidence.",
      "A reviewed clean reinstall is required because no verified previous generation can be restored.",
      "No automatic deletion or guessed generation selection is permitted.",
    ]),
  });
}

export async function inspectRemoteSetupRepair(
  config: RemoteSetupConfig,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteSetupRepairPlan> {
  return planFromInspection(await inspectRemoteSynchronizationTransaction(config, transport));
}

async function restorePublicVerificationMaterial(config: RemoteSetupConfig, transport: RemoteAdminTransport): Promise<void> {
  const transfers: readonly [string, string][] = [
    [config.remote.configPath, `${config.policyConfigPath}.dispatcher.json`],
    [`${config.remote.configPath}.capability.json`, `${config.policyConfigPath}.capability.json`],
    [`${config.remote.configPath}.declaration.json`, `${config.policyConfigPath}.declaration.json`],
    [`${config.remote.configPath}.declaration-binding.json`, `${config.policyConfigPath}.declaration-binding.json`],
    [`${config.remote.configPath}.response-public.pem`, `${config.policyConfigPath}.response-public.pem`],
    ["/etc/opshaven/approval-public.pem", config.local.operatorPublicKeyFile],
  ];
  for (const [remote, local] of transfers) {
    const result = await transport.download(remote, local);
    if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", `Restored public verification artifact could not be downloaded: ${remote}.`, true);
  }
}

function verifyRestoredInstalledState(installed: InstalledRemoteState, expectedGeneration: number | null): void {
  if (installed.status !== "complete" || installed.recordedIdentityMatches !== true || installed.generation === null) throw new OpsHavenError("POLICY_DENIED", "The restored generation is not a complete recorded canonical state.");
  if (expectedGeneration !== null && installed.generation !== expectedGeneration) throw new OpsHavenError("POLICY_DENIED", "The restored installation generation does not match the recorded previous generation.");
  for (const [label, digest] of Object.entries({
    runtime: installed.runtimeSha256,
    dispatcher: installed.dispatcherSha256,
    authorization: installed.capabilityIdentitySha256,
    declaration: installed.declarationSha256,
    policy: installed.policySha256,
  })) if (!digest) throw new OpsHavenError("POLICY_DENIED", `The restored ${label} identity is unavailable.`);
}

async function auditRepair(config: RemoteSetupConfig, plan: RemoteSetupRepairPlan, installed: InstalledRemoteState): Promise<string> {
  const policy = await loadConfig(config.policyConfigPath);
  const evidenceDigest = sha256({
    transactionId: plan.transactionId,
    previousGeneration: plan.previousGeneration,
    installedGeneration: installed.generation,
    runtime: installed.runtimeSha256,
    dispatcher: installed.dispatcherSha256,
    authorization: installed.capabilityIdentitySha256,
    declaration: installed.declarationSha256,
    policy: installed.policySha256,
  });
  await new AuditLog(policy.audit.path).append({
    timestamp: new Date().toISOString(),
    requestId: randomBytes(12).toString("hex"),
    actor: "operator-cli",
    operation: "remote_setup_repair",
    resourceId: "remote.setup",
    mutation: plan.action === "restore-previous",
    dryRun: false,
    outcome: "success",
    evidenceDigest,
  });
  return evidenceDigest;
}

export async function repairRemoteSetup(
  config: RemoteSetupConfig,
  approved: boolean,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteSetupRepairReceipt> {
  const inspection = await inspectRemoteSynchronizationTransaction(config, transport);
  const plan = planFromInspection(inspection);
  if (plan.action === "none") {
    const installed = await readInstalledRemoteState(config, transport);
    const auditEvidenceDigest = await auditRepair(config, plan, installed);
    return Object.freeze({ ok: true, action: "none", transactionId: plan.transactionId, restoredGenerationIdentity: plan.previousGeneration, installedGeneration: installed.generation, boundary: null, auditEvidenceDigest, repairedAt: new Date().toISOString() });
  }
  if (plan.action === "clean-reinstall-required") throw new OpsHavenError("POLICY_DENIED", "No verified previous generation is available for automatic restoration. Preserve the evidence and run the reviewed clean reinstall flow.", false, { repairPlan: plan, safeNextCommand: "opshaven setup repair --clean-reinstall --approve" });
  if (!approved) throw new OpsHavenError("POLICY_DENIED", "Synchronization repair requires explicit approval.", false, { repairPlan: plan });
  if (!inspection.transaction || !plan.transactionId) throw new OpsHavenError("POLICY_DENIED", "The reviewed repair transaction is unavailable.");
  const expectedInstalledGeneration = inspection.transaction.previousGenerationAvailable ? Math.max(1, (inspection.transaction as unknown as { previousInstallationGeneration?: number }).previousInstallationGeneration ?? 1) : null;
  const rollback = await rollbackRecordedSynchronization(config, plan.transactionId, plan.previousGeneration, transport);
  await restorePublicVerificationMaterial(config, transport);
  const boundary = await certifyRemoteBoundary(config);
  if (!boundary.ok) throw new OpsHavenError("POLICY_DENIED", "The restored generation failed security-boundary verification.");
  const installed = await readInstalledRemoteState(config, transport);
  verifyRestoredInstalledState(installed, expectedInstalledGeneration === 1 ? null : expectedInstalledGeneration);
  await advanceRemoteSynchronizationTransaction(config, plan.transactionId, "ROLLBACK_CLEANUP", undefined, transport);
  const auditEvidenceDigest = await auditRepair(config, plan, installed);
  return Object.freeze({
    ok: true,
    action: "restore-previous",
    transactionId: plan.transactionId,
    restoredGenerationIdentity: rollback.restoredGenerationIdentity,
    installedGeneration: installed.generation,
    boundary,
    auditEvidenceDigest,
    repairedAt: new Date().toISOString(),
  });
}
