import assert from "node:assert/strict";
import test from "node:test";
import type { RemoteManagedFootprint } from "../src/setup/footprint.js";
import { evaluateInstallationHealth } from "../src/setup/health.js";
import type { InstalledRemoteState, RemoteStateComparison } from "../src/setup/state.js";
import type { SynchronizationTransactionInspection } from "../src/setup/transaction-inspection.js";

const digest = "a".repeat(64);

function installed(overrides: Partial<InstalledRemoteState> = {}): InstalledRemoteState {
  return Object.freeze({
    status: "complete",
    source: "installed remote state",
    schemaVersion: 3,
    generation: 4,
    recordedIdentityMatches: true,
    sourceSha: "1".repeat(40),
    dispatcherMode: "controlled",
    runtimeSha256: digest,
    dispatcherSha256: digest,
    policyVersion: "fixture",
    policySha256: digest,
    capabilityIdentitySha256: digest,
    capabilityArtifactSha256: digest,
    declarationSha256: digest,
    operatorVerificationIdentity: digest,
    applicationScope: Object.freeze(["sample-api"]),
    applicationScopeSha256: digest,
    platform: "Linux",
    architecture: "x86_64",
    nodeVersion: "v22.18.0",
    ...overrides,
  });
}

function transaction(overrides: Partial<SynchronizationTransactionInspection> = {}): SynchronizationTransactionInspection {
  return Object.freeze({
    status: "absent",
    transaction: null,
    integrityValid: true,
    hostBindingValid: true,
    rollbackAvailable: false,
    activeGenerationCertain: true,
    lastCompletedPhase: null,
    ...overrides,
  });
}

function footprint(kind: RemoteManagedFootprint["kind"], overrides: Partial<RemoteManagedFootprint> = {}): RemoteManagedFootprint {
  return Object.freeze({
    version: 1,
    kind,
    present: Object.freeze(kind === "empty" ? [] : ["/var/lib/opshaven/remote-state.json"]),
    missing: Object.freeze(kind === "canonical-pair" ? [] : ["/var/lib/opshaven/setup-receipt.json"]),
    receiptPresent: kind === "canonical-pair",
    statePresent: kind !== "empty" && kind !== "legacy",
    transactionPresent: false,
    detail: kind === "empty" ? "no OpsHaven-managed remote state was found" : `${kind} fixture`,
    ...overrides,
  });
}

function comparison(value: InstalledRemoteState, compatible = true): RemoteStateComparison {
  return Object.freeze({
    desired: Object.freeze({
      schemaVersion: 3,
      sourceSha: "1".repeat(40),
      dispatcherMode: "controlled",
      runtimeSha256: digest,
      dispatcherSha256: digest,
      policyVersion: "fixture",
      policySha256: digest,
      capabilityIdentitySha256: digest,
      declarationSha256: digest,
      operatorVerificationIdentity: digest,
      applicationScope: Object.freeze(["sample-api"]),
      applicationScopeSha256: digest,
      minimumNodeMajor: 22,
    }),
    installed: value,
    changeType: compatible ? "NO_CHANGE" : "AUTHORIZATION_ONLY",
    reasons: Object.freeze(compatible ? [] : ["authorization differs"]),
    compatible,
  });
}

test("fresh remote state is absent and installable, not repairable", () => {
  const value = installed({
    status: "absent",
    schemaVersion: null,
    generation: null,
    recordedIdentityMatches: null,
    sourceSha: null,
    dispatcherMode: null,
    runtimeSha256: null,
    dispatcherSha256: null,
    policyVersion: null,
    policySha256: null,
    capabilityIdentitySha256: null,
    capabilityArtifactSha256: null,
    declarationSha256: null,
    operatorVerificationIdentity: null,
    applicationScope: Object.freeze([]),
    applicationScopeSha256: null,
    platform: null,
    architecture: null,
    nodeVersion: null,
  });
  const health = evaluateInstallationHealth(value, transaction(), null, footprint("empty"));
  assert.equal(health.primary, "REMOTE_ABSENT");
  assert.equal(health.repairRequired, false);
  assert.equal(health.safeNextCommand, "opshaven setup remote");
});

test("partial generation without a transaction requires evidence-preserving reinstall", () => {
  const value = installed({ status: "absent", generation: null, recordedIdentityMatches: null });
  const health = evaluateInstallationHealth(value, transaction(), null, footprint("partial"));
  assert.equal(health.primary, "REMOTE_GENERATION_PARTIAL");
  assert.equal(health.repairRequired, true);
  assert.equal(health.repairClassification, "EVIDENCE_PRESERVING_REINSTALL");
  assert.equal(health.deploymentAllowed, false);
  assert.equal(health.boundaryCertificationAllowed, false);
});

test("known legacy runtime selects explicit migration rather than fresh install", () => {
  const value = installed({ status: "absent", generation: null, recordedIdentityMatches: null });
  const health = evaluateInstallationHealth(value, transaction(), null, footprint("legacy"));
  assert.ok(health.states.includes("REMOTE_LEGACY"));
  assert.equal(health.repairClassification, "MIGRATE_LEGACY_STATE");
  assert.equal(health.migrationStatus, "required");
});

test("interrupted transaction with verified rollback material restores previous generation", () => {
  const record = Object.freeze({
    version: 1 as const,
    transactionId: "b".repeat(32),
    phase: "VERIFY_ACTIVE" as const,
    changeType: "RUNTIME_AND_DISPATCHER" as const,
    hostBindingSha256: digest,
    desiredGenerationIdentity: "c".repeat(64),
    previousGenerationIdentity: "d".repeat(64),
    previousGenerationAvailable: true,
    snapshotRoot: `/var/lib/opshaven/transactions/${"b".repeat(32)}/previous`,
    createdAt: "2026-08-01T18:00:00.000Z",
    updatedAt: "2026-08-01T18:01:00.000Z",
    integritySha256: "e".repeat(64),
  });
  const health = evaluateInstallationHealth(
    installed(),
    transaction({ status: "unresolved", transaction: record, rollbackAvailable: true, activeGenerationCertain: false, lastCompletedPhase: "VERIFY_ACTIVE" }),
    comparison(installed()),
    footprint("canonical-pair"),
  );
  assert.equal(health.primary, "REMOTE_TRANSACTION_INCOMPLETE");
  assert.equal(health.repairClassification, "RESTORE_PREVIOUS_GENERATION");
  assert.ok(health.states.includes("REMOTE_ROLLBACK_AVAILABLE"));
});

test("recorded identity mismatch invalidates deployment and boundary readiness", () => {
  const value = installed({ recordedIdentityMatches: false, detail: "recorded remote state differs from installed dispatcherSha256" });
  const health = evaluateInstallationHealth(value, transaction(), comparison(value), footprint("canonical-pair"));
  assert.equal(health.primary, "REMOTE_RECEIPT_INVALID");
  assert.equal(health.receiptValidity, "invalid");
  assert.equal(health.deploymentAllowed, false);
  assert.equal(health.boundaryCertificationAllowed, false);
});

test("one verified canonical state enables deployment readiness", () => {
  const value = installed();
  const health = evaluateInstallationHealth(value, transaction(), comparison(value), footprint("canonical-pair"));
  assert.equal(health.primary, "REMOTE_HEALTHY_DEPLOYMENT");
  assert.equal(health.repairRequired, false);
  assert.equal(health.deploymentAllowed, true);
  assert.equal(health.boundaryCertificationAllowed, true);
});

test("unsafe unknown footprint fails closed for manual recovery", () => {
  const health = evaluateInstallationHealth(installed(), transaction(), comparison(installed()), footprint("unsafe"));
  assert.equal(health.primary, "REMOTE_STATE_UNCERTAIN");
  assert.equal(health.repairClassification, "MANUAL_RECOVERY_REQUIRED");
  assert.equal(health.synchronizationAllowed, false);
});
