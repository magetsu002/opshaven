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
    schemaVersion: 2,
    sourceSha: "1".repeat(40),
    dispatcherMode: "controlled",
    runtimeSha256: "2".repeat(64),
    dispatcherSha256: "3".repeat(64),
    policySha256: "4".repeat(64),
    capabilityIdentitySha256: "5".repeat(64),
    declarationSha256: "6".repeat(64),
    operatorVerificationIdentity: "7".repeat(64),
    applicationScope: ["app.sample-api"],
    applicationScopeSha256: "8".repeat(64),
  };
}

function installed(overrides: Partial<InstalledRemoteState> = {}): InstalledRemoteState {
  const expected = desired();
  return {
    status: "complete",
    source: "installed remote state",
    schemaVersion: 2,
    generation: 1,
    sourceSha: expected.sourceSha,
    dispatcherMode: expected.dispatcherMode,
    runtimeSha256: expected.runtimeSha256,
    dispatcherSha256: expected.dispatcherSha256,
    policySha256: expected.policySha256,
    capabilityIdentitySha256: expected.capabilityIdentitySha256,
    capabilityArtifactSha256: "9".repeat(64),
    declarationSha256: expected.declarationSha256,
    operatorVerificationIdentity: expected.operatorVerificationIdentity,
    applicationScope: expected.applicationScope,
    applicationScopeSha256: expected.applicationScopeSha256,
    platform: "Linux",
    architecture: "x86_64",
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

test("inconsistent recorded state fails closed instead of being inferred as valid", () => {
  const comparison = compareRemoteState(desired(), installed({ status: "inconsistent", detail: "recorded state differs from installed artifacts" }));
  assert.equal(comparison.compatible, false);
  assert.equal(comparison.changeType, "REPAIR_REQUIRED");
  assert.match(comparison.reasons[0] ?? "", /recorded state differs/);
});

test("sanitized compatibility diagnostics identify the stale side", () => {
  const comparison = compareRemoteState(desired(), installed({ dispatcherMode: "read-only", capabilityIdentitySha256: "d".repeat(64), applicationScope: [], applicationScopeSha256: "e".repeat(64) }));
  const details = compatibilityDetails(comparison);
  assert.equal(details.expectedDispatcherMode, "controlled");
  assert.equal(details.installedDispatcherMode, "read-only");
  assert.match(String(details.expectedCapabilityDigest), /^sha256:[a-f0-9]{64}$/);
  assert.match(String(details.installedCapabilityDigest), /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(details.expectedApplicationScope, ["app.sample-api"]);
  assert.deepEqual(details.installedApplicationScope, []);
  assert.match(String(details.diagnosis), /dispatcher mode/);
  assert.doesNotMatch(JSON.stringify(details), /PRIVATE KEY|approvalToken|Bearer/);
});
