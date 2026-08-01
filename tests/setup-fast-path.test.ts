import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { OpsHavenError } from "../src/errors.js";
import { executeRemoteSetup, type RemoteSetupEngineDependencies } from "../src/setup/engine.js";
import type { SetupPresenter } from "../src/setup/presentation.js";
import type { RemoteSetupConfig, RemoteSetupPlan } from "../src/setup/remote.js";
import type { DesiredRemoteState, InstalledRemoteState, RemoteStateComparison, RemoteSetupChangeType } from "../src/setup/state.js";

interface Calls { preflight: number; install: number; trust: number; synchronize: number; certify: number; readiness: number; rollback: number }
type AbortPhase = "synchronize" | "readiness" | undefined;

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
function installed(expected: DesiredRemoteState): InstalledRemoteState {
  return {
    status: "complete",
    source: "installed remote state",
    schemaVersion: 3,
    generation: 1,
    recordedIdentityMatches: true,
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
  };
}
function comparison(): RemoteStateComparison {
  const expected = desired();
  return { desired: expected, installed: installed(expected), changeType: "NO_CHANGE", reasons: [], compatible: true };
}
async function fixture(): Promise<{ root: string; config: RemoteSetupConfig }> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-fast-setup-"));
  return {
    root,
    config: {
      version: 1,
      policyConfigPath: path.join(root, "config.json"),
      expectedSourceSha: "1".repeat(40),
      target: { host: "example.invalid", port: 22, adminUser: "root", knownHostsFile: path.join(root, "known_hosts"), identityFile: path.join(root, "identity"), expectedHostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", privilege: "root" },
      local: { runtimeRoot: path.join(root, "dist"), dispatcherPath: path.join(root, "dist/src/remote/dispatcher.js"), wrapperTemplatePath: path.join(root, "wrapper"), capabilityDeclarationPath: path.join(root, "declaration.json"), operatorPrivateKeyFile: path.join(root, "private.pem"), operatorPublicKeyFile: path.join(root, "public.pem"), restrictedAuthorizedKeyFile: path.join(root, "restricted.pub") },
      remote: { account: "opshaven", runtimeRoot: "/usr/lib/opshaven", configPath: "/etc/opshaven/config.json", wrapperPath: "/usr/local/bin/opshaven-readonly-force-command", stateDirectory: "/var/lib/opshaven", receiptPath: "/var/lib/opshaven/setup-receipt.json", nodeCandidates: ["/usr/bin/node"] },
      trust: { expiresInSeconds: 3600 },
    },
  };
}
function plan(changeType: RemoteSetupChangeType): RemoteSetupPlan {
  return { version: 1, sourceSha: "1".repeat(40), target: "root@example.invalid:22", changeType, changes: [], estimatedDuration: "fixture", mutations: [] };
}
function presenter(): SetupPresenter {
  return { plan: () => undefined, step: () => undefined, progress: () => undefined, cancellation: () => undefined, fingerprint: () => undefined, approve: async () => true, receipt: () => undefined };
}
function dependencies(calls: Calls, controller?: AbortController, abortPhase?: AbortPhase, rollbackFails = false): RemoteSetupEngineDependencies {
  return {
    preflight: async () => {
      calls.preflight += 1;
      return { ok: true, checkedAt: new Date().toISOString(), nodePath: "/usr/bin/node", remote: { platform: "Linux", distribution: "ubuntu", version: "24.04", architecture: "x86_64", nodePath: "/usr/bin/node", nodeVersion: "v22.0.0", freeBytes: 999999999, installation: { accountExists: true, runtimeExists: true, wrapperExists: true, configExists: true, receiptExists: true } }, checks: [] };
    },
    install: async () => {
      calls.install += 1;
      return { ok: true, changed: [], runtimeTreeSha256: "2".repeat(64), backupRoot: "/var/lib/opshaven/backups/runtimefixture", receiptId: "runtimefixture" };
    },
    trust: async () => {
      calls.trust += 1;
      return { ok: true, mode: "controlled", synchronizationKind: "runtime-install", receiptId: "runtimefixture", backupRoot: "/var/lib/opshaven/backups/runtimefixture", dispatcherSha256: "3".repeat(64), capabilitySha256: "a".repeat(64), declarationSha256: "6".repeat(64), bindingSha256: "b".repeat(64), responsePublicKeySha256: "c".repeat(64), expiresAt: new Date(Date.now() + 60000).toISOString(), installedPaths: [], changed: [] };
    },
    synchronize: async () => {
      calls.synchronize += 1;
      if (abortPhase === "synchronize") controller?.abort();
      return { ok: true, mode: "controlled", synchronizationKind: "authorization-sync", receiptId: "syncfixture", backupRoot: "/var/lib/opshaven/backups/syncfixture", dispatcherSha256: "3".repeat(64), capabilitySha256: "a".repeat(64), declarationSha256: "6".repeat(64), bindingSha256: "b".repeat(64), responsePublicKeySha256: "c".repeat(64), expiresAt: new Date(Date.now() + 60000).toISOString(), installedPaths: [], changed: ["/etc/opshaven/config.json.capability.json"] };
    },
    certify: async () => {
      calls.certify += 1;
      return { ok: true, certifiedAt: new Date().toISOString(), boundarySha256: "d".repeat(64), assertions: [] };
    },
    rollback: async () => {
      calls.rollback += 1;
      if (rollbackFails) throw new Error("fixture rollback failure");
      return { ok: true, action: "rollback", completedAt: new Date().toISOString(), restored: ["/etc/opshaven/config.json.capability.json"], removed: [], preserved: [] };
    },
    desired: async () => desired(),
    readiness: async () => {
      calls.readiness += 1;
      if (abortPhase === "readiness") controller?.abort();
      return comparison();
    },
    verifyReadiness: async () => {
      calls.readiness += 1;
      if (abortPhase === "readiness") controller?.abort();
      return comparison();
    },
  };
}
const zero = (): Calls => ({ preflight: 0, install: 0, trust: 0, synchronize: 0, certify: 0, readiness: 0, rollback: 0 });

async function setup(changeType: RemoteSetupChangeType, calls: Calls): Promise<ReturnType<typeof executeRemoteSetup>> {
  const value = await fixture();
  try {
    return await executeRemoteSetup(value.config, plan(changeType), { approved: true, nonInteractive: true, tui: false, json: true, presenter: presenter(), dependencies: dependencies(calls) });
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
}

test("no-change setup performs no runtime or authorization mutation but still verifies", async () => {
  const calls = zero();
  const receipt = await setup("NO_CHANGE", calls);
  assert.equal(receipt.outcome, "SETUP_NO_CHANGE");
  assert.equal(receipt.changeType, "NO_CHANGE");
  assert.deepEqual(calls, { ...zero(), certify: 1, readiness: 1 });
});

test("authorization and declaration fast paths reuse the verified runtime", async () => {
  for (const changeType of ["AUTHORIZATION_ONLY", "APPLICATION_DECLARATION_ONLY", "AUTHORIZATION_AND_DECLARATION"] as const) {
    const calls = zero();
    const receipt = await setup(changeType, calls);
    assert.equal(receipt.outcome, "SETUP_SUCCEEDED");
    assert.equal(receipt.changeType, changeType);
    assert.equal(receipt.installation, undefined);
    assert.equal(receipt.trust?.synchronizationKind, "authorization-sync");
    assert.deepEqual(calls, { ...zero(), synchronize: 1, certify: 1, readiness: 1 });
  }
});

test("cancellation before mutation reports no-mutation outcome and does not roll back", async () => {
  const value = await fixture();
  const calls = zero();
  const controller = new AbortController();
  controller.abort();
  try {
    await assert.rejects(
      executeRemoteSetup(value.config, plan("AUTHORIZATION_ONLY"), { approved: true, nonInteractive: true, tui: false, json: true, presenter: presenter(), dependencies: dependencies(calls), signal: controller.signal }),
      (error: unknown) => error instanceof OpsHavenError && error.safeDetails?.setupOutcome === "SETUP_CANCELLED_NO_MUTATION",
    );
    assert.equal(calls.rollback, 0);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("cancellation after authorization mutation rolls back at the next atomic checkpoint", async () => {
  const value = await fixture();
  const calls = zero();
  const controller = new AbortController();
  try {
    await assert.rejects(
      executeRemoteSetup(value.config, plan("AUTHORIZATION_ONLY"), { approved: true, nonInteractive: true, tui: false, json: true, presenter: presenter(), dependencies: dependencies(calls, controller, "synchronize"), signal: controller.signal }),
      (error: unknown) => error instanceof OpsHavenError && error.safeDetails?.setupOutcome === "SETUP_CANCELLED_ROLLED_BACK" && error.safeDetails?.rerunSafe === true,
    );
    assert.equal(calls.synchronize, 1);
    assert.equal(calls.rollback, 1);
    assert.equal(calls.certify, 0);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("cancellation during final readiness cannot escape as setup success", async () => {
  const value = await fixture();
  const calls = zero();
  const controller = new AbortController();
  try {
    await assert.rejects(
      executeRemoteSetup(value.config, plan("AUTHORIZATION_ONLY"), { approved: true, nonInteractive: true, tui: false, json: true, presenter: presenter(), dependencies: dependencies(calls, controller, "readiness"), signal: controller.signal }),
      (error: unknown) => error instanceof OpsHavenError && error.safeDetails?.setupOutcome === "SETUP_CANCELLED_ROLLED_BACK",
    );
    assert.equal(calls.certify, 1);
    assert.equal(calls.readiness, 1);
    assert.equal(calls.rollback, 1);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("rollback failure remains a distinct blocked recovery outcome", async () => {
  const value = await fixture();
  const calls = zero();
  const controller = new AbortController();
  try {
    await assert.rejects(
      executeRemoteSetup(value.config, plan("AUTHORIZATION_ONLY"), { approved: true, nonInteractive: true, tui: false, json: true, presenter: presenter(), dependencies: dependencies(calls, controller, "synchronize", true), signal: controller.signal }),
      (error: unknown) => error instanceof OpsHavenError && error.safeDetails?.setupOutcome === "SETUP_FAILED_ROLLBACK_FAILED" && error.safeDetails?.rollbackCompleted === false,
    );
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});
