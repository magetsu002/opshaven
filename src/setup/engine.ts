import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { AuditLog } from "../audit.js";
import { sha256 } from "../canonical.js";
import { loadConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { certifyRemoteBoundary, type RemoteBoundaryReceipt } from "./certify.js";
import { installRestrictedRuntime, type RemoteInstallResult } from "./install.js";
import {
  cleanupLocalSynchronizationState,
  restoreLocalSynchronizationState,
  snapshotLocalSynchronizationState,
  type LocalSynchronizationSnapshot,
} from "./local-transaction.js";
import { createSetupPresenter, type SetupPresenter } from "./presentation.js";
import { assertRemoteSetupPreflight, preflightRemoteSetup, type RemoteSetupPreflightReport } from "./preflight.js";
import type { RemoteSetupConfig, RemoteSetupPlan, SetupReceipt } from "./remote.js";
import { rollbackRemoteSetup, type RemoteCleanupReceipt } from "./rollback.js";
import {
  buildDesiredRemoteState,
  compareRemoteState,
  prepareRemoteState,
  recordVerifiedRemoteState,
  type DesiredRemoteState,
  type RemoteSetupChangeType,
  type RemoteStateComparison,
} from "./state.js";
import {
  advanceRemoteSynchronizationTransaction,
  beginRemoteSynchronizationTransaction,
  rollbackRemoteSynchronizationTransaction,
  type RemoteSynchronizationTransaction,
  type RemoteTransactionRollbackReceipt,
  type SynchronizationPhase,
} from "./transaction.js";
import { provisionRemoteTrust, synchronizeRemoteTrust, type RemoteTrustReceipt } from "./trust.js";

export type RemoteSetupOutcome =
  | "SETUP_SUCCEEDED"
  | "SETUP_NO_CHANGE"
  | "SETUP_FAILED_NO_MUTATION"
  | "SETUP_FAILED_ROLLED_BACK"
  | "SETUP_FAILED_ROLLBACK_FAILED"
  | "SETUP_CANCELLED_NO_MUTATION"
  | "SETUP_CANCELLED_ROLLED_BACK";

export interface SetupTimings { readonly [phase: string]: number }
export interface RemoteSetupLifecycleReceipt extends SetupReceipt {
  readonly outcome: "SETUP_SUCCEEDED" | "SETUP_NO_CHANGE";
  readonly changeType?: RemoteSetupChangeType;
  readonly timings?: SetupTimings;
  readonly preflight?: RemoteSetupPreflightReport;
  readonly installation?: RemoteInstallResult;
  readonly trust?: RemoteTrustReceipt;
  readonly boundary: RemoteBoundaryReceipt;
  readonly canonicalState?: RemoteStateComparison;
  readonly transaction?: RemoteSynchronizationTransaction;
}
export interface RemoteSetupEngineDependencies {
  preflight(config: RemoteSetupConfig): Promise<RemoteSetupPreflightReport>;
  install(config: RemoteSetupConfig, preflight: RemoteSetupPreflightReport): Promise<RemoteInstallResult>;
  trust(config: RemoteSetupConfig, installation: RemoteInstallResult, desired?: DesiredRemoteState): Promise<RemoteTrustReceipt>;
  synchronize?(config: RemoteSetupConfig, desired?: DesiredRemoteState): Promise<RemoteTrustReceipt>;
  certify(config: RemoteSetupConfig): Promise<RemoteBoundaryReceipt>;
  rollback(config: RemoteSetupConfig): Promise<RemoteCleanupReceipt>;
  desired?(config: RemoteSetupConfig): Promise<DesiredRemoteState>;
  readiness?(config: RemoteSetupConfig, desired: DesiredRemoteState, boundary: RemoteBoundaryReceipt): Promise<RemoteStateComparison>;
  verifyReadiness?(config: RemoteSetupConfig): Promise<RemoteStateComparison>;
  beginTransaction?(config: RemoteSetupConfig, desired: DesiredRemoteState, changeType: RemoteSetupChangeType): Promise<RemoteSynchronizationTransaction>;
  advanceTransaction?(config: RemoteSetupConfig, transactionId: string, phase: SynchronizationPhase, lastError?: string): Promise<RemoteSynchronizationTransaction>;
  rollbackTransaction?(config: RemoteSetupConfig, transactionId: string): Promise<RemoteTransactionRollbackReceipt>;
}
export interface RemoteSetupEngineOptions {
  readonly nonInteractive: boolean;
  readonly tui: boolean;
  readonly approved: boolean;
  readonly json: boolean;
  readonly presenter?: SetupPresenter;
  readonly dependencies?: RemoteSetupEngineDependencies;
  readonly signal?: AbortSignal;
  readonly initialTimings?: Readonly<Record<string, number>>;
}

const DEFAULT_DEPENDENCIES: RemoteSetupEngineDependencies = Object.freeze({
  preflight: async (config: RemoteSetupConfig): Promise<RemoteSetupPreflightReport> => await preflightRemoteSetup(config),
  install: async (config: RemoteSetupConfig, report: RemoteSetupPreflightReport): Promise<RemoteInstallResult> => await installRestrictedRuntime(config, report),
  trust: async (config: RemoteSetupConfig, installation: RemoteInstallResult, desired?: DesiredRemoteState): Promise<RemoteTrustReceipt> => await provisionRemoteTrust(config, installation, undefined, desired),
  synchronize: async (config: RemoteSetupConfig, desired?: DesiredRemoteState): Promise<RemoteTrustReceipt> => await synchronizeRemoteTrust(config, desired),
  certify: async (config: RemoteSetupConfig): Promise<RemoteBoundaryReceipt> => await certifyRemoteBoundary(config),
  rollback: async (config: RemoteSetupConfig): Promise<RemoteCleanupReceipt> => await rollbackRemoteSetup(config, true),
  desired: async (config: RemoteSetupConfig): Promise<DesiredRemoteState> => await buildDesiredRemoteState(config),
  readiness: async (config: RemoteSetupConfig, desired: DesiredRemoteState, boundary: RemoteBoundaryReceipt): Promise<RemoteStateComparison> => compareRemoteState(desired, await recordVerifiedRemoteState(config, desired, boundary.boundarySha256)),
  verifyReadiness: async (config: RemoteSetupConfig): Promise<RemoteStateComparison> => await prepareRemoteState(config),
  beginTransaction: async (config: RemoteSetupConfig, desired: DesiredRemoteState, changeType: RemoteSetupChangeType): Promise<RemoteSynchronizationTransaction> => await beginRemoteSynchronizationTransaction(config, desired, changeType),
  advanceTransaction: async (config: RemoteSetupConfig, transactionId: string, phase: SynchronizationPhase, lastError?: string): Promise<RemoteSynchronizationTransaction> => await advanceRemoteSynchronizationTransaction(config, transactionId, phase, lastError),
  rollbackTransaction: async (config: RemoteSetupConfig, transactionId: string): Promise<RemoteTransactionRollbackReceipt> => await rollbackRemoteSynchronizationTransaction(config, transactionId),
});

function isMutating(changeType: RemoteSetupChangeType): boolean { return changeType !== "NO_CHANGE" && changeType !== "REPAIR_REQUIRED"; }
function requiresRuntime(changeType: RemoteSetupChangeType): boolean { return changeType === "FULL_INSTALL" || changeType === "RUNTIME_UPDATE" || changeType === "DISPATCHER_UPDATE"; }
function requiresAuthorizationOnly(changeType: RemoteSetupChangeType): boolean {
  return changeType === "AUTHORIZATION_ONLY" || changeType === "APPLICATION_DECLARATION_ONLY" || changeType === "AUTHORIZATION_AND_DECLARATION";
}
function checkCancellation(signal: AbortSignal | undefined, mutationStarted: boolean): void {
  if (signal?.aborted) throw new OpsHavenError("CANCELLED", mutationStarted ? "Remote setup cancellation was requested after activation began." : "Remote setup was cancelled before activation.", false, { mutationStarted });
}
function setupFailure(error: unknown, outcome: RemoteSetupOutcome, details: Record<string, unknown> = {}): OpsHavenError {
  const source = error instanceof OpsHavenError ? error : new OpsHavenError("INTERNAL_ERROR", error instanceof Error ? error.message : "The operation failed safely.");
  return new OpsHavenError(source.code, source.message, source.retryable, Object.freeze({ ...(source.safeDetails ?? {}), setupOutcome: outcome, ...details }));
}
function lowerLevelDiagnostic(error: unknown): string {
  const message = error instanceof Error ? error.message : "unknown lower-level failure";
  return message.replace(/[\r\n\u001b\u009b]/g, " ").slice(0, 500);
}

async function timed<T>(presenter: SetupPresenter, timings: Record<string, number>, phase: string, progressId: string, detail: string, work: () => Promise<T>): Promise<T> {
  const started = Date.now();
  let timer: ReturnType<typeof setInterval> | undefined;
  const cadence = presenter.heartbeatMs?.() ?? 15000;
  if (presenter.progress) timer = setInterval(() => presenter.progress?.(progressId, detail, Date.now() - started), cadence);
  try { return await work(); }
  finally { if (timer) clearInterval(timer); timings[phase] = Date.now() - started; }
}

async function auditCancellation(config: RemoteSetupConfig, changeType: RemoteSetupChangeType, mutationStarted: boolean): Promise<void> {
  try {
    const policy = await loadConfig(config.policyConfigPath);
    await new AuditLog(policy.audit.path).append({ timestamp: new Date().toISOString(), requestId: randomBytes(12).toString("hex"), actor: "operator-cli", operation: "remote_setup_cancellation", resourceId: "remote.setup", mutation: mutationStarted, dryRun: !mutationStarted, outcome: "failure", errorCode: "CANCELLED", evidenceDigest: sha256({ changeType, mutationStarted }) });
  } catch { /* cancellation must not be hidden by secondary audit failure */ }
}

async function writeLocalReceipt(config: RemoteSetupConfig, receipt: RemoteSetupLifecycleReceipt): Promise<void> {
  const filePath = `${config.policyConfigPath}.setup-receipt.json`;
  const temporary = `${filePath}.opshaven-${process.pid}`;
  try { await fs.writeFile(temporary, `${JSON.stringify(receipt)}\n`, { mode: 0o600 }); await fs.chmod(temporary, 0o600); await fs.rename(temporary, filePath); }
  finally { await fs.rm(temporary, { force: true }); }
}

async function advance(
  dependencies: RemoteSetupEngineDependencies,
  config: RemoteSetupConfig,
  transaction: RemoteSynchronizationTransaction | undefined,
  phase: SynchronizationPhase,
  lastError?: string,
): Promise<RemoteSynchronizationTransaction | undefined> {
  if (!transaction || !dependencies.advanceTransaction) return transaction;
  return await dependencies.advanceTransaction(config, transaction.transactionId, phase, lastError);
}

export async function executeRemoteSetup(config: RemoteSetupConfig, plan: RemoteSetupPlan, options: RemoteSetupEngineOptions): Promise<RemoteSetupLifecycleReceipt> {
  const presenter = options.presenter ?? createSetupPresenter({ tui: options.tui, nonInteractive: options.nonInteractive, preapproved: options.approved, json: options.json });
  const dependencies = options.dependencies ?? DEFAULT_DEPENDENCIES;
  const timings: Record<string, number> = { ...(options.initialTimings ?? {}) };
  presenter.plan(plan);
  presenter.fingerprint("SSH host key", config.target.expectedHostKeySha256);
  presenter.fingerprint("source head", config.expectedSourceSha);
  if (plan.changeType === "REPAIR_REQUIRED") throw setupFailure(new OpsHavenError("POLICY_DENIED", "Remote state cannot be synchronized safely. Run the reviewed recovery flow before continuing."), "SETUP_FAILED_NO_MUTATION", { safeNextCommand: "opshaven setup repair" });
  if (isMutating(plan.changeType) && !(await presenter.approve("Apply the exact reviewed remote changes above?"))) throw setupFailure(new OpsHavenError("POLICY_DENIED", "Remote setup was not explicitly approved."), "SETUP_FAILED_NO_MUTATION");

  const startedAt = new Date().toISOString();
  let mutationStarted = false;
  let preflight: RemoteSetupPreflightReport | undefined;
  let installation: RemoteInstallResult | undefined;
  let trust: RemoteTrustReceipt | undefined;
  let boundary: RemoteBoundaryReceipt;
  let canonicalState: RemoteStateComparison | undefined;
  let transaction: RemoteSynchronizationTransaction | undefined;
  let localSnapshot: LocalSynchronizationSnapshot | undefined;
  const desired = dependencies.desired ? await timed(presenter, timings, "artifactPreparation", "inspection", "building reviewed content identities", async () => await dependencies.desired?.(config) as DesiredRemoteState) : undefined;
  const transactional = isMutating(plan.changeType) && desired !== undefined && dependencies.beginTransaction !== undefined && dependencies.advanceTransaction !== undefined && dependencies.rollbackTransaction !== undefined;

  try {
    checkCancellation(options.signal, false);
    if (requiresRuntime(plan.changeType)) {
      presenter.step("preflight", "local", "pending", "verifying local identity and remote prerequisites");
      preflight = await timed(presenter, timings, "remotePlatformInspection", "preflight", "checking remote platform and permissions", async () => await dependencies.preflight(config));
      if (!preflight.ok) { presenter.step("preflight", "local", "failed", preflight.checks.filter((item) => item.state === "failed").map((item) => item.id).join(", ")); assertRemoteSetupPreflight(preflight); }
      presenter.step("preflight", "local", "passed", `${preflight.remote?.distribution} ${preflight.remote?.version}, Node ${preflight.remote?.nodeVersion}`);
      checkCancellation(options.signal, false);
    }

    if (transactional && desired) {
      localSnapshot = await snapshotLocalSynchronizationState(config);
      // RECORD_PREVIOUS is the mandatory commit barrier before ACTIVATE.
      transaction = await timed(presenter, timings, "recordPreviousGeneration", "preflight", "recording the previous verified generation", async () => await dependencies.beginTransaction?.(config, desired, plan.changeType) as RemoteSynchronizationTransaction);
      if (transaction.phase !== "RECORD_PREVIOUS") throw new OpsHavenError("POLICY_DENIED", "Remote synchronization did not record a rollback-safe previous generation.");
      transaction = await advance(dependencies, config, transaction, "STAGE");
      transaction = await advance(dependencies, config, transaction, "VERIFY_STAGED");
      checkCancellation(options.signal, false);
      transaction = await advance(dependencies, config, transaction, "ACTIVATE");
    }

    if (requiresRuntime(plan.changeType)) {
      mutationStarted = true;
      presenter.step("runtime-install", "vps", "pending", "installing the atomic restricted runtime");
      installation = await timed(presenter, timings, "runtimeInstallation", "runtime-install", "uploading and verifying reviewed runtime artifacts", async () => await dependencies.install(config, preflight as RemoteSetupPreflightReport));
      presenter.step("runtime-install", "vps", "passed", installation.changed.length ? `${installation.changed.length} reviewed paths changed` : "runtime already current");
      presenter.fingerprint("runtime tree", installation.runtimeTreeSha256);
      checkCancellation(options.signal, true);
      presenter.step("trust", "local", "pending", "signing and applying controlled authorization material");
      trust = await timed(presenter, timings, "authorizationSynchronization", "trust", "uploading verified signed authorization", async () => await dependencies.trust(config, installation as RemoteInstallResult, desired));
    } else if (requiresAuthorizationOnly(plan.changeType)) {
      if (!dependencies.synchronize) throw new OpsHavenError("INTERNAL_ERROR", "Authorization synchronization is unavailable.");
      mutationStarted = true;
      presenter.step("runtime-install", "vps", "skipped", "existing runtime verified and reused");
      presenter.step("trust", "local", "pending", plan.changeType === "APPLICATION_DECLARATION_ONLY" ? "updating only reviewed application declaration state" : "updating only changed signed authorization state");
      trust = await timed(presenter, timings, "authorizationSynchronization", "trust", "uploading one authorization generation", async () => await dependencies.synchronize?.(config, desired) as RemoteTrustReceipt);
    } else {
      presenter.step("preflight", "local", "skipped", "verified installed state already available");
      presenter.step("runtime-install", "vps", "skipped", "runtime content identity matches");
      presenter.step("trust", "vps", "skipped", "authorization content identity matches");
    }
    if (trust) {
      if (desired && trust.mode !== "controlled") throw new OpsHavenError("POLICY_DENIED", "Remote authorization was generated for an incompatible dispatcher mode.");
      presenter.step("trust", "vps", "passed", trust.changed?.length ? `${trust.changed.length} signed-state paths changed` : "authorization already current");
      presenter.fingerprint("dispatcher", trust.dispatcherSha256);
      presenter.fingerprint("capability", trust.capabilitySha256);
    }

    transaction = await advance(dependencies, config, transaction, "VERIFY_ACTIVE");
    checkCancellation(options.signal, mutationStarted);
    presenter.step("boundary", "vps", "pending", "executing authenticated deployment boundary certification");
    boundary = await timed(presenter, timings, "boundaryVerification", "boundary", "running signature, replay, denial, and scope checks", async () => await dependencies.certify(config));
    presenter.step("boundary", "vps", "passed", `${boundary.assertions.length} assertions passed`);
    presenter.fingerprint("boundary receipt", boundary.boundarySha256);
    checkCancellation(options.signal, mutationStarted);
    presenter.step("readiness", "vps", "pending", "comparing installed state with reviewed deployment state");
    if (plan.changeType === "NO_CHANGE") {
      if (!dependencies.verifyReadiness) throw new OpsHavenError("INTERNAL_ERROR", "Readiness verification is unavailable.");
      canonicalState = await timed(presenter, timings, "readinessVerification", "readiness", "rechecking canonical content identities", async () => await dependencies.verifyReadiness?.(config) as RemoteStateComparison);
    } else if (desired && dependencies.readiness) {
      canonicalState = await timed(presenter, timings, "readinessVerification", "readiness", "recording the verified synchronization generation", async () => await dependencies.readiness?.(config, desired, boundary) as RemoteStateComparison);
    }
    if (canonicalState && !canonicalState.compatible) throw new OpsHavenError("POLICY_DENIED", "Remote setup postconditions did not reach deployment-ready state.", false, { changeType: canonicalState.changeType, expectedMode: canonicalState.desired.dispatcherMode, observedMode: canonicalState.installed.dispatcherMode ?? "unknown" });
    checkCancellation(options.signal, mutationStarted);
    presenter.step("readiness", "vps", "passed", "runtime, dispatcher, authorization, policy, and application scope match");
    transaction = await advance(dependencies, config, transaction, "COMMIT");
    transaction = await advance(dependencies, config, transaction, "CLEANUP");
  } catch (error) {
    const cancelled = error instanceof OpsHavenError && error.code === "CANCELLED";
    if (cancelled) await auditCancellation(config, plan.changeType, mutationStarted);
    let restored = false;
    let rollbackReceipt: RemoteTransactionRollbackReceipt | RemoteCleanupReceipt | undefined;
    if (mutationStarted) {
      presenter.step("rollback", "vps", "pending", "restoring the previous verified synchronization generation");
      try {
        if (transaction && dependencies.rollbackTransaction) {
          rollbackReceipt = await dependencies.rollbackTransaction(config, transaction.transactionId);
          if (localSnapshot) await restoreLocalSynchronizationState(localSnapshot);
          const restoredBoundary = await dependencies.certify(config);
          if (!restoredBoundary.ok) throw new OpsHavenError("POLICY_DENIED", "The restored generation did not pass security-boundary verification.");
        } else {
          rollbackReceipt = await dependencies.rollback(config);
        }
        restored = true;
        presenter.step("rollback", "vps", "rolled-back", `${rollbackReceipt.restored.length} restored, ${rollbackReceipt.removed.length} removed`);
      } catch (rollbackError) {
        if (transaction && dependencies.advanceTransaction) {
          try { transaction = await dependencies.advanceTransaction(config, transaction.transactionId, "ROLLBACK_START", lowerLevelDiagnostic(rollbackError)); } catch { /* retain original recovery failure */ }
        }
        presenter.step("rollback", "vps", "failed", "previous generation could not be restored; deployment operations are blocked");
        if (cancelled) presenter.cancellation?.(true, false);
        await cleanupLocalSynchronizationState(localSnapshot);
        throw setupFailure(
          new OpsHavenError("POLICY_DENIED", "Remote synchronization failed and the previous verified generation could not be restored. Deployment operations are blocked until the reviewed recovery flow succeeds."),
          "SETUP_FAILED_ROLLBACK_FAILED",
          {
            mutationStarted: true,
            rollbackStarted: true,
            rollbackCompleted: false,
            transactionId: transaction?.transactionId,
            desiredGeneration: transaction?.desiredGenerationIdentity,
            previousGeneration: transaction?.previousGenerationIdentity,
            previousGenerationAvailable: transaction?.previousGenerationAvailable ?? false,
            failedVerificationStage: transaction?.phase ?? "unknown",
            blockedOperations: Object.freeze(["deployment planning", "deployment apply", "remote setup success certification"]),
            safeOperations: Object.freeze(["opshaven doctor --debug", "opshaven setup repair"]),
            safeNextCommand: "opshaven setup repair",
            rollbackDebug: lowerLevelDiagnostic(rollbackError),
          },
        );
      }
    } else if (transaction) {
      try { transaction = await advance(dependencies, config, transaction, "CLEANUP", lowerLevelDiagnostic(error)); } catch { /* no active generation changed */ }
    }
    await cleanupLocalSynchronizationState(localSnapshot);
    if (cancelled) presenter.cancellation?.(mutationStarted, restored);
    const outcome: RemoteSetupOutcome = cancelled
      ? mutationStarted ? "SETUP_CANCELLED_ROLLED_BACK" : "SETUP_CANCELLED_NO_MUTATION"
      : mutationStarted ? "SETUP_FAILED_ROLLED_BACK" : "SETUP_FAILED_NO_MUTATION";
    throw setupFailure(error, outcome, {
      mutationStarted,
      rollbackStarted: mutationStarted,
      rollbackCompleted: restored,
      rerunSafe: !mutationStarted || restored,
      transactionId: transaction?.transactionId,
      activeGeneration: restored ? transaction?.previousGenerationIdentity : undefined,
      previousGeneration: transaction?.previousGenerationIdentity,
      safeNextCommand: restored ? "opshaven doctor" : "opshaven setup repair",
    });
  }

  await cleanupLocalSynchronizationState(localSnapshot);
  const outcome = plan.changeType === "NO_CHANGE" ? "SETUP_NO_CHANGE" : "SETUP_SUCCEEDED";
  const receipt: RemoteSetupLifecycleReceipt = Object.freeze({
    version: 1,
    outcome,
    receiptId: trust?.receiptId ?? installation?.receiptId ?? `verify${randomBytes(8).toString("hex")}`,
    sourceSha: config.expectedSourceSha,
    target: plan.target,
    dryRun: false,
    startedAt,
    finishedAt: new Date().toISOString(),
    certified: true,
    changeType: plan.changeType,
    timings: Object.freeze({ ...timings }),
    mutations: plan.mutations,
    checks: Object.freeze([...(preflight?.checks ?? []), ...boundary.assertions.map((item) => ({ id: `boundary:${item.name}`, state: item.passed ? "passed" as const : "failed" as const, detail: item.detail })), ...(canonicalState ? [{ id: "deployment-readiness", state: canonicalState.compatible ? "passed" as const : "failed" as const, detail: canonicalState.changeType }] : [])]),
    rollback: Object.freeze({ required: false, attempted: false, completed: false, restored: Object.freeze([]) }),
    ...(preflight ? { preflight } : {}),
    ...(installation ? { installation } : {}),
    ...(trust ? { trust } : {}),
    boundary,
    ...(canonicalState ? { canonicalState } : {}),
    ...(transaction ? { transaction } : {}),
  });
  await writeLocalReceipt(config, receipt);
  presenter.receipt(receipt);
  return receipt;
}
