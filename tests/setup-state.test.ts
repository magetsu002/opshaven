import assert from "node:assert/strict";
import test from "node:test";
import {
  compatibilityDetails,
  compareRemoteState,
  type DesiredRemoteState,
  type InstalledRemoteState,
} from "../src/setup/state.js";

function desired(): DesiredRemoteState {
  return {
    schemaVersion: 3,
    sourceSha: "1".repeat(40),
    dispatcherMode: "controlled",
    runtimeSha256: "2".repeat(64),
    dispatcherSha256: "3".repeat(64),
    policyVersion: "deployment-v3",
    policySha256: "4".repeat(64),
    capabilityIdentitySha256: "5".repeat(64),
    declarationSha256: "6".repeat(64),
    operatorVerificationIdentity: "7".repeat(64),
    applicationScope: ["app.sample-api"],
    applicationScopeSha256: "8".repeat(64),
    minimumNodeMajor: 22,
  };
}

function installed(overrides: Partial<InstalledRemoteState> = {}): InstalledRemoteState {
  const expected = desired();
  return {
    status: "complete",
    source: "installed remote state",
    schemaVersion: 3,
    generation: 1,
    sourceSha: expected.sourceSha,
    dispatcherMode: expected.dispatcherMode,
    runtimeSha256: expected.runtimeSha256,
    dispatcherSha256: expected.dispatcherSha256,
    policyVersion: expected.policyVersion,
    policySha256: expected.policySha256,
    capabilityIdentitySha256: expected.capabilityIdentitySha256,
    capabilityArtifactSha256: "9".repeat(64),
    declarationSha256: expected.declarationSha256,
    operatorVerificationIdentity: expected.operatorVerificationIdentity,
    applicationScope: expected.applicationScope,
    applicationScopeSha256: expected.applicationScopeSha256,
    platform: "Linux",
    architecture: "x86_64",
    nodeVersion: "v22.23.1",
    ...overrides,
  };
}

test("reproduced read-only dispatcher mismatch is a required dispatcher update", () => {
  const comparison = compareRemoteState(desired(), installed({
    dispatcherMode: "read-only",
    dispatcherSha256: "a".repeat(64),
    capabilityIdentitySha256: "b".repeat(64),
    applicationScope: [],
    applicationScopeSha256: "c".repeat(64),
  }));
  assert.equal(comparison.compatible, false);
  assert.equal(comparison.changeType, "DISPATCHER_UPDATE");
  assert.match(comparison.reasons.join("; "), /dispatcher mode is read-only, expected controlled/);
});

test("identical desired and installed content identity produces no change", () => {
  const comparison = compareRemoteState(desired(), installed());
  assert.equal(comparison.compatible, true);
  assert.equal(comparison.changeType, "NO_CHANGE");
  assert.deepEqual(comparison.reasons, []);
});

test("authorization-only, declaration-only, and combined changes remain explicit", () => {
  assert.equal(compareRemoteState(desired(), installed({ policyVersion: "deployment-v2", policySha256: "a".repeat(64) })).changeType, "AUTHORIZATION_ONLY");
  assert.equal(compareRemoteState(desired(), installed({ declarationSha256: "b".repeat(64) })).changeType, "APPLICATION_DECLARATION_ONLY");
  assert.equal(compareRemoteState(desired(), installed({ policySha256: "c".repeat(64), declarationSha256: "d".repeat(64) })).changeType, "AUTHORIZATION_AND_DECLARATION");
  assert.equal(compareRemoteState(desired(), installed({ schemaVersion: 2 })).changeType, "APPLICATION_DECLARATION_ONLY");
});

test("runtime and dispatcher identities take precedence over authorization synchronization", () => {
  assert.equal(compareRemoteState(desired(), installed({ sourceSha: "a".repeat(40) })).changeType, "RUNTIME_UPDATE");
  assert.equal(compareRemoteState(desired(), installed({ runtimeSha256: "b".repeat(64), policySha256: "c".repeat(64) })).changeType, "RUNTIME_UPDATE");
  assert.equal(compareRemoteState(desired(), installed({ dispatcherSha256: "d".repeat(64), declarationSha256: "e".repeat(64) })).changeType, "DISPATCHER_UPDATE");
});

test("inconsistent or unsupported remote identity fails closed instead of being inferred as valid", () => {
  const inconsistent = compareRemoteState(desired(), installed({ status: "inconsistent", detail: "recorded state differs from installed artifacts" }));
  assert.equal(inconsistent.changeType, "REPAIR_REQUIRED");
  assert.match(inconsistent.reasons[0] ?? "", /recorded state differs/);
  assert.equal(compareRemoteState(desired(), installed({ schemaVersion: 4 })).changeType, "REPAIR_REQUIRED");
  assert.equal(compareRemoteState(desired(), installed({ platform: "Darwin" })).changeType, "REPAIR_REQUIRED");
  assert.equal(compareRemoteState(desired(), installed({ architecture: "mips" })).changeType, "REPAIR_REQUIRED");
  assert.equal(compareRemoteState(desired(), installed({ nodeVersion: "v20.19.0" })).changeType, "REPAIR_REQUIRED");
});

test("sanitized compatibility diagnostics identify every compared state class", () => {
  const comparison = compareRemoteState(desired(), installed({ dispatcherMode: "read-only", capabilityIdentitySha256: "d".repeat(64), applicationScope: [], applicationScopeSha256: "e".repeat(64) }));
  const details = compatibilityDetails(comparison);
  assert.equal(details.expectedDispatcherMode, "controlled");
  assert.equal(details.installedDispatcherMode, "legacy-read-only");
  assert.match(String(details.expectedRuntimeDigest), /^sha256:[a-f0-9]{64}$/);
  assert.match(String(details.installedRuntimeDigest), /^sha256:[a-f0-9]{64}$/);
  assert.match(String(details.expectedCapabilityDigest), /^sha256:[a-f0-9]{64}$/);
  assert.match(String(details.installedCapabilityDigest), /^sha256:[a-f0-9]{64}$/);
  assert.match(String(details.expectedDeclarationDigest), /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(details.expectedApplicationScope, ["app.sample-api"]);
  assert.deepEqual(details.installedApplicationScope, []);
  assert.equal(details.installedPlatform, "Linux");
  assert.equal(details.installedArchitecture, "x86_64");
  assert.equal(details.installedNodeVersion, "v22.23.1");
  assert.equal(details.repair, "opshaven setup remote");
  assert.match(String(details.diagnosis), /dispatcher mode/);
  assert.doesNotMatch(JSON.stringify(details), /PRIVATE KEY|approvalToken|Bearer/);
});
