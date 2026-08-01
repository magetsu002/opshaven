import { promises as fs } from "node:fs";
import { OpsHavenError } from "../errors.js";
import { certifyRemoteBoundary, type RemoteBoundaryReceipt } from "./certify.js";
import { installRestrictedRuntime, type RemoteInstallResult } from "./install.js";
import { createSetupPresenter, type SetupPresenter } from "./presentation.js";
import { assertRemoteSetupPreflight, preflightRemoteSetup, type RemoteSetupPreflightReport } from "./preflight.js";
import type { RemoteSetupConfig, RemoteSetupPlan, SetupReceipt } from "./remote.js";
import { rollbackRemoteSetup, type RemoteCleanupReceipt } from "./rollback.js";
import { buildDesiredRemoteState, compareRemoteState, recordVerifiedRemoteState, type DesiredRemoteState, type RemoteStateComparison } from "./state.js";
import { provisionRemoteTrust, type RemoteTrustReceipt } from "./trust.js";
export interface RemoteSetupLifecycleReceipt extends SetupReceipt { readonly preflight: RemoteSetupPreflightReport; readonly installation: RemoteInstallResult; readonly trust: RemoteTrustReceipt; readonly boundary: RemoteBoundaryReceipt; readonly canonicalState?: RemoteStateComparison }
export interface RemoteSetupEngineDependencies { preflight(config: RemoteSetupConfig): Promise<RemoteSetupPreflightReport>; install(config: RemoteSetupConfig, preflight: RemoteSetupPreflightReport): Promise<RemoteInstallResult>; trust(config: RemoteSetupConfig, installation: RemoteInstallResult, desired?: DesiredRemoteState): Promise<RemoteTrustReceipt>; certify(config: RemoteSetupConfig): Promise<RemoteBoundaryReceipt>; rollback(config: RemoteSetupConfig): Promise<RemoteCleanupReceipt>; desired?(config: RemoteSetupConfig): Promise<DesiredRemoteState>; readiness?(config: RemoteSetupConfig, desired: DesiredRemoteState, boundary: RemoteBoundaryReceipt): Promise<RemoteStateComparison> }
export interface RemoteSetupEngineOptions { readonly nonInteractive: boolean; readonly tui: boolean; readonly approved: boolean; readonly json: boolean; readonly presenter?: SetupPresenter; readonly dependencies?: RemoteSetupEngineDependencies }
const DEFAULT_DEPENDENCIES: RemoteSetupEngineDependencies = Object.freeze({
  preflight: async (config: RemoteSetupConfig): Promise<RemoteSetupPreflightReport> => await preflightRemoteSetup(config),
  install: async (config: RemoteSetupConfig, report: RemoteSetupPreflightReport): Promise<RemoteInstallResult> => await installRestrictedRuntime(config, report),
  trust: async (config: RemoteSetupConfig, installation: RemoteInstallResult, desired?: DesiredRemoteState): Promise<RemoteTrustReceipt> => await provisionRemoteTrust(config, installation, undefined, desired),
  certify: async (config: RemoteSetupConfig): Promise<RemoteBoundaryReceipt> => await certifyRemoteBoundary(config),
  rollback: async (config: RemoteSetupConfig): Promise<RemoteCleanupReceipt> => await rollbackRemoteSetup(config, true),
  desired: async (config: RemoteSetupConfig): Promise<DesiredRemoteState> => await buildDesiredRemoteState(config),
  readiness: async (config: RemoteSetupConfig, desired: DesiredRemoteState, boundary: RemoteBoundaryReceipt): Promise<RemoteStateComparison> => compareRemoteState(desired, await recordVerifiedRemoteState(config, desired, boundary.boundarySha256)),
});
async function writeLocalReceipt(config: RemoteSetupConfig, receipt: RemoteSetupLifecycleReceipt): Promise<void> { const filePath = `${config.policyConfigPath}.setup-receipt.json`; const temporary = `${filePath}.opshaven-${process.pid}`; try { await fs.writeFile(temporary, `${JSON.stringify(receipt)}\n`, { mode: 0o600 }); await fs.chmod(temporary, 0o600); await fs.rename(temporary, filePath); } finally { await fs.rm(temporary, { force: true }); } }
export async function executeRemoteSetup(config: RemoteSetupConfig, plan: RemoteSetupPlan, options: RemoteSetupEngineOptions): Promise<RemoteSetupLifecycleReceipt> {
  const presenter = options.presenter ?? createSetupPresenter({ tui: options.tui, nonInteractive: options.nonInteractive, preapproved: options.approved, json: options.json });
  const dependencies = options.dependencies ?? DEFAULT_DEPENDENCIES;
  presenter.plan(plan); presenter.fingerprint("SSH host key", config.target.expectedHostKeySha256); presenter.fingerprint("source head", config.expectedSourceSha);
  if (!(await presenter.approve("Apply the exact reviewed VPS mutations above?"))) throw new OpsHavenError("POLICY_DENIED", "Remote setup was not explicitly approved.");
  const startedAt = new Date().toISOString(); presenter.step("preflight", "local", "pending", "verifying local identity and remote prerequisites");
  const preflight = await dependencies.preflight(config); if (!preflight.ok) { presenter.step("preflight", "local", "failed", preflight.checks.filter((item) => item.state === "failed").map((item) => item.id).join(", ")); assertRemoteSetupPreflight(preflight); }
  presenter.step("preflight", "local", "passed", `${preflight.remote?.distribution} ${preflight.remote?.version}, Node ${preflight.remote?.nodeVersion}`);
  const desired = dependencies.desired ? await dependencies.desired(config) : undefined;
  presenter.step("runtime-install", "vps", "pending", "installing the atomic restricted runtime"); const installation = await dependencies.install(config, preflight);
  presenter.step("runtime-install", "vps", "passed", installation.changed.length ? `${installation.changed.length} paths changed` : "already at requested state"); presenter.fingerprint("runtime tree", installation.runtimeTreeSha256);
  let trust: RemoteTrustReceipt; let boundary: RemoteBoundaryReceipt; let canonicalState: RemoteStateComparison | undefined;
  try {
    presenter.step("trust", "local", "pending", "signing and verifying controlled authorization material"); trust = await dependencies.trust(config, installation, desired);
    if (desired && trust.mode !== "controlled") throw new OpsHavenError("POLICY_DENIED", "Remote authorization was generated for an incompatible dispatcher mode.");
    presenter.step("trust", "vps", "passed", `controlled authorization expires ${trust.expiresAt}`); presenter.fingerprint("dispatcher", trust.dispatcherSha256); presenter.fingerprint("capability", trust.capabilitySha256);
    presenter.step("boundary", "vps", "pending", "executing authenticated deployment boundary certification"); boundary = await dependencies.certify(config); presenter.step("boundary", "vps", "passed", `${boundary.assertions.length} assertions passed`); presenter.fingerprint("boundary receipt", boundary.boundarySha256);
    if (desired && dependencies.readiness) { presenter.step("readiness", "vps", "pending", "comparing installed state with reviewed deployment state"); canonicalState = await dependencies.readiness(config, desired, boundary); if (!canonicalState.compatible) throw new OpsHavenError("POLICY_DENIED", "Remote setup postconditions did not reach deployment-ready state.", false, { changeType: canonicalState.changeType, expectedMode: canonicalState.desired.dispatcherMode, observedMode: canonicalState.installed.dispatcherMode ?? "unknown" }); presenter.step("readiness", "vps", "passed", "runtime, dispatcher, authorization, policy, and application scope match"); }
  } catch (error) {
    presenter.step("rollback", "vps", "pending", "restoring the prior verified state after post-install failure");
    try { const rollback = await dependencies.rollback(config); presenter.step("rollback", "vps", "rolled-back", `${rollback.restored.length} restored, ${rollback.removed.length} removed`); }
    catch (rollbackError) { presenter.step("rollback", "vps", "failed", "automatic rollback failed; inspect the protected remote receipt and backups"); throw new OpsHavenError("POLICY_DENIED", `Remote setup failed and rollback also failed: ${rollbackError instanceof Error ? rollbackError.message : "unknown rollback failure"}.`); }
    throw error;
  }
  const receipt: RemoteSetupLifecycleReceipt = Object.freeze({ version: 1, receiptId: installation.receiptId, sourceSha: config.expectedSourceSha, target: plan.target, dryRun: false, startedAt, finishedAt: new Date().toISOString(), certified: true, mutations: plan.mutations, checks: Object.freeze([...preflight.checks, ...boundary.assertions.map((item) => ({ id: `boundary:${item.name}`, state: item.passed ? "passed" as const : "failed" as const, detail: item.detail })), ...(canonicalState ? [{ id: "deployment-readiness", state: canonicalState.compatible ? "passed" as const : "failed" as const, detail: canonicalState.changeType }] : [])]), rollback: Object.freeze({ required: false, attempted: false, completed: false, restored: Object.freeze([]) }), preflight, installation, trust, boundary, ...(canonicalState ? { canonicalState } : {}) });
  await writeLocalReceipt(config, receipt); presenter.receipt(receipt); return receipt;
}
