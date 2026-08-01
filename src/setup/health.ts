import type { RemoteSetupConfig } from "./remote.js";
import { prepareRemoteState, readInstalledRemoteState, type InstalledRemoteState, type RemoteStateComparison } from "./state.js";
import { inspectRemoteSynchronizationTransaction, type SynchronizationTransactionInspection } from "./transaction-inspection.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export type InstallationHealthState =
  | "UNINITIALIZED"
  | "LOCAL_READY"
  | "REMOTE_ABSENT"
  | "REMOTE_LEGACY"
  | "REMOTE_HEALTHY_READ_ONLY"
  | "REMOTE_HEALTHY_DEPLOYMENT"
  | "REMOTE_SYNC_REQUIRED"
  | "REMOTE_REPAIR_REQUIRED"
  | "REMOTE_TRANSACTION_INCOMPLETE"
  | "REMOTE_GENERATION_PARTIAL"
  | "REMOTE_RECEIPT_INVALID"
  | "REMOTE_ROLLBACK_AVAILABLE"
  | "REMOTE_ROLLBACK_UNAVAILABLE"
  | "REMOTE_STATE_UNCERTAIN";

export type RepairClassification =
  | "NO_REPAIR_NEEDED"
  | "COMPLETE_INTERRUPTED_TRANSACTION"
  | "RESTORE_PREVIOUS_GENERATION"
  | "REBUILD_ACTIVE_RECEIPT"
  | "MIGRATE_LEGACY_STATE"
  | "CLEAN_INCOMPLETE_STAGING"
  | "EVIDENCE_PRESERVING_REINSTALL"
  | "MANUAL_RECOVERY_REQUIRED";

export interface InstallationHealthReport {
  readonly version: 1;
  readonly primary: InstallationHealthState;
  readonly states: readonly InstallationHealthState[];
  readonly repairClassification: RepairClassification;
  readonly repairRequired: boolean;
  readonly synchronizationAllowed: boolean;
  readonly boundaryCertificationAllowed: boolean;
  readonly deploymentAllowed: boolean;
  readonly reasons: readonly string[];
  readonly safeNextCommand: string | null;
  readonly installed: InstalledRemoteState;
  readonly transaction: SynchronizationTransactionInspection;
  readonly comparison: RemoteStateComparison | null;
  readonly activeGeneration: number | null;
  readonly previousGenerationIdentity: string | null;
  readonly receiptValidity: "valid" | "invalid" | "unavailable";
  readonly migrationStatus: "not-required" | "required" | "unknown";
}

const SEVERITY: Readonly<Record<InstallationHealthState, number>> = Object.freeze({
  REMOTE_STATE_UNCERTAIN: 100,
  REMOTE_RECEIPT_INVALID: 95,
  REMOTE_GENERATION_PARTIAL: 94,
  REMOTE_TRANSACTION_INCOMPLETE: 93,
  REMOTE_REPAIR_REQUIRED: 90,
  REMOTE_LEGACY: 70,
  REMOTE_SYNC_REQUIRED: 60,
  REMOTE_ABSENT: 50,
  UNINITIALIZED: 40,
  LOCAL_READY: 30,
  REMOTE_ROLLBACK_UNAVAILABLE: 20,
  REMOTE_ROLLBACK_AVAILABLE: 10,
  REMOTE_HEALTHY_READ_ONLY: 1,
  REMOTE_HEALTHY_DEPLOYMENT: 0,
});

function unique(values: readonly InstallationHealthState[]): readonly InstallationHealthState[] {
  return Object.freeze([...new Set(values)].sort((left, right) => SEVERITY[right] - SEVERITY[left]));
}

function primary(states: readonly InstallationHealthState[]): InstallationHealthState {
  return states[0] ?? "REMOTE_STATE_UNCERTAIN";
}

function partialDetail(installed: InstalledRemoteState): boolean {
  return /partial|incomplete|missing while managed artifacts remain|missing generation|missing or unsafe state artifact/i.test(installed.detail ?? "");
}

function receiptDetail(installed: InstalledRemoteState): boolean {
  return /receipt|recorded remote state differs|integrity|generation chain/i.test(installed.detail ?? "");
}

function legacyDetail(installed: InstalledRemoteState): boolean {
  return installed.schemaVersion !== null && installed.schemaVersion < 3
    || /legacy|pre-canonical|read-only dispatcher|split dispatcher/i.test(installed.detail ?? "");
}

function repairForTransaction(transaction: SynchronizationTransactionInspection): RepairClassification {
  if (transaction.status === "unresolved" && transaction.integrityValid && transaction.hostBindingValid) {
    if (transaction.rollbackAvailable && transaction.transaction?.previousGenerationAvailable) return "RESTORE_PREVIOUS_GENERATION";
    if (transaction.lastCompletedPhase === "STAGE" || transaction.lastCompletedPhase === "VERIFY_STAGED") return "CLEAN_INCOMPLETE_STAGING";
    return "COMPLETE_INTERRUPTED_TRANSACTION";
  }
  return "EVIDENCE_PRESERVING_REINSTALL";
}

export function evaluateInstallationHealth(
  installed: InstalledRemoteState,
  transaction: SynchronizationTransactionInspection,
  comparison: RemoteStateComparison | null = null,
): InstallationHealthReport {
  const states: InstallationHealthState[] = [];
  const reasons: string[] = [];
  let repairClassification: RepairClassification = "NO_REPAIR_NEEDED";
  let migrationStatus: InstallationHealthReport["migrationStatus"] = "not-required";

  const transactionUncertain = transaction.status === "invalid"
    || !transaction.integrityValid
    || !transaction.hostBindingValid;
  const transactionIncomplete = transaction.status === "unresolved" || !transaction.activeGenerationCertain;

  if (transactionUncertain) {
    states.push("REMOTE_STATE_UNCERTAIN", "REMOTE_REPAIR_REQUIRED");
    reasons.push(transaction.detail ?? "synchronization transaction evidence is invalid or bound to another host");
    repairClassification = "EVIDENCE_PRESERVING_REINSTALL";
  } else if (transactionIncomplete) {
    states.push("REMOTE_TRANSACTION_INCOMPLETE", "REMOTE_REPAIR_REQUIRED");
    reasons.push(`synchronization transaction is incomplete at ${transaction.lastCompletedPhase ?? "an unknown phase"}`);
    repairClassification = repairForTransaction(transaction);
  }

  if (transaction.rollbackAvailable) states.push("REMOTE_ROLLBACK_AVAILABLE");
  else if (transactionIncomplete || transactionUncertain) states.push("REMOTE_ROLLBACK_UNAVAILABLE");

  if (installed.status === "absent") {
    if (!transactionIncomplete && !transactionUncertain) {
      states.push("REMOTE_ABSENT");
      reasons.push("no installed OpsHaven generation was found");
    }
  } else if (installed.status === "inconsistent") {
    states.push("REMOTE_REPAIR_REQUIRED");
    reasons.push(installed.detail ?? "installed generation evidence is inconsistent");
    if (legacyDetail(installed)) {
      states.push("REMOTE_LEGACY");
      migrationStatus = "required";
      repairClassification = repairClassification === "NO_REPAIR_NEEDED" ? "MIGRATE_LEGACY_STATE" : repairClassification;
    } else if (partialDetail(installed)) {
      states.push("REMOTE_GENERATION_PARTIAL");
      repairClassification = transaction.rollbackAvailable ? "RESTORE_PREVIOUS_GENERATION" : "EVIDENCE_PRESERVING_REINSTALL";
    } else if (receiptDetail(installed)) {
      states.push("REMOTE_RECEIPT_INVALID");
      repairClassification = "EVIDENCE_PRESERVING_REINSTALL";
    } else {
      states.push("REMOTE_STATE_UNCERTAIN");
      migrationStatus = "unknown";
      repairClassification = "MANUAL_RECOVERY_REQUIRED";
    }
  } else {
    if (legacyDetail(installed)) {
      states.push("REMOTE_LEGACY", "REMOTE_SYNC_REQUIRED");
      reasons.push(`installed state schema ${installed.schemaVersion ?? "unknown"} requires explicit migration`);
      migrationStatus = "required";
      repairClassification = "MIGRATE_LEGACY_STATE";
    }
    if (installed.recordedIdentityMatches === false) {
      states.push("REMOTE_RECEIPT_INVALID", "REMOTE_REPAIR_REQUIRED");
      reasons.push(installed.detail ?? "recorded generation identity does not match installed artifacts");
      repairClassification = "EVIDENCE_PRESERVING_REINSTALL";
    }
    if (comparison?.changeType === "REPAIR_REQUIRED") {
      states.push("REMOTE_REPAIR_REQUIRED");
      reasons.push(...comparison.reasons);
      if (repairClassification === "NO_REPAIR_NEEDED") repairClassification = "EVIDENCE_PRESERVING_REINSTALL";
    } else if (comparison && !comparison.compatible) {
      states.push("REMOTE_SYNC_REQUIRED");
      reasons.push(...comparison.reasons);
    } else if (!states.some((state) => state.startsWith("REMOTE_REPAIR") || state === "REMOTE_RECEIPT_INVALID" || state === "REMOTE_LEGACY")) {
      states.push(installed.dispatcherMode === "read-only" ? "REMOTE_HEALTHY_READ_ONLY" : "REMOTE_HEALTHY_DEPLOYMENT");
    }
  }

  const ordered = unique(states.length ? states : ["REMOTE_STATE_UNCERTAIN"]);
  const repairRequired = ordered.some((state) => [
    "REMOTE_REPAIR_REQUIRED",
    "REMOTE_TRANSACTION_INCOMPLETE",
    "REMOTE_GENERATION_PARTIAL",
    "REMOTE_RECEIPT_INVALID",
    "REMOTE_STATE_UNCERTAIN",
  ].includes(state));
  const deploymentAllowed = ordered.includes("REMOTE_HEALTHY_DEPLOYMENT") && !repairRequired && comparison?.compatible !== false;
  const boundaryCertificationAllowed = (ordered.includes("REMOTE_HEALTHY_DEPLOYMENT") || ordered.includes("REMOTE_HEALTHY_READ_ONLY"))
    && !repairRequired
    && comparison?.compatible !== false;
  const synchronizationAllowed = !repairRequired && !ordered.includes("REMOTE_STATE_UNCERTAIN");
  const safeNextCommand = repairRequired
    ? "opshaven setup repair"
    : ordered.includes("REMOTE_LEGACY") || ordered.includes("REMOTE_SYNC_REQUIRED") || ordered.includes("REMOTE_ABSENT")
      ? "opshaven setup remote"
      : null;

  return Object.freeze({
    version: 1,
    primary: primary(ordered),
    states: ordered,
    repairClassification,
    repairRequired,
    synchronizationAllowed,
    boundaryCertificationAllowed,
    deploymentAllowed,
    reasons: Object.freeze([...new Set(reasons)]),
    safeNextCommand,
    installed,
    transaction,
    comparison,
    activeGeneration: installed.generation,
    previousGenerationIdentity: transaction.transaction?.previousGenerationIdentity ?? null,
    receiptValidity: installed.status === "complete" && installed.recordedIdentityMatches === true
      ? "valid"
      : installed.status === "absent"
        ? "unavailable"
        : "invalid",
    migrationStatus,
  });
}

export async function inspectInstallationHealth(
  config: RemoteSetupConfig,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
  includeDesiredComparison = true,
): Promise<InstallationHealthReport> {
  if (includeDesiredComparison) {
    const [comparison, transaction] = await Promise.all([
      prepareRemoteState(config, transport),
      inspectRemoteSynchronizationTransaction(config, transport),
    ]);
    return evaluateInstallationHealth(comparison.installed, transaction, comparison);
  }
  const [installed, transaction] = await Promise.all([
    readInstalledRemoteState(config, transport),
    inspectRemoteSynchronizationTransaction(config, transport),
  ]);
  return evaluateInstallationHealth(installed, transaction, null);
}
