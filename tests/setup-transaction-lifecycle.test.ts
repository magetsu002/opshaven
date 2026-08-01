import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { OpsHavenError } from "../src/errors.js";
import { executeRemoteSetup, type RemoteSetupEngineDependencies } from "../src/setup/engine.js";
import type { SetupPresenter } from "../src/setup/presentation.js";
import type { RemoteSetupConfig, RemoteSetupPlan } from "../src/setup/remote.js";
import type { DesiredRemoteState, InstalledRemoteState, RemoteStateComparison } from "../src/setup/state.js";
import type { RemoteSynchronizationTransaction, SynchronizationPhase } from "../src/setup/transaction.js";

interface Calls {
  preflight: number;
  runtimeInstall: number;
  dispatcherInstall: number;
  dependencyInstall: number;
  synchronize: number;
  certify: number;
  rollback: number;
}

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
    generation: 2,
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

function compatible(): RemoteStateComparison {
  const expected = desired();
  return { desired: expected, installed: installed(expected), changeType: "NO_CHANGE", reasons: [], compatible: true };
}

async function fixture(): Promise<{ root: string; config: RemoteSetupConfig }> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-transaction-test-"));
  const config: RemoteSetupConfig = {
    version: 1,
    policyConfigPath: path.join(root, "config.json"),
    expectedSourceSha: "1".repeat(40),
    target: { host: "example.invalid", port: 22, adminUser: "root", knownHostsFile: path.join(root, "known_hosts"), identityFile: path.join(root, "identity"), expectedHostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", privilege: "root" },
    local: { runtimeRoot: path.join(root, "dist"), dispatcherPath: path.join(root, "dist/src/remote/dispatcher.js"), wrapperTemplatePath: path.join(root, "wrapper"), capabilityDeclarationPath: path.join(root, "declaration.json"), operatorPrivateKeyFile: path.join(root, "private.pem"), operatorPublicKeyFile: path.join(root, "public.pem"), restrictedAuthorizedKeyFile: path.join(root, "restricted.pub") },
    remote: { account: "opshaven", runtimeRoot: "/usr/lib/opshaven", configPath: "/etc/opshaven/config.json", wrapperPath: "/usr/local/bin/opshaven-readonly-force-command", stateDirectory: "/var/lib/opshaven", receiptPath: "/var/lib/opshaven/setup-receipt.json", nodeCandidates: ["/usr/bin/node"] },
    trust: { expiresInSeconds: 3600 },
  };
  await fs.writeFile(config.policyConfigPath, "{}\n", { mode: 0o600 });
  return { root, config };
}

function plan(): RemoteSetupPlan {
  return {
    version: 1,
    sourceSha: "1".repeat(40),
    target: "root@example.invalid:22",
    changeType: "DISPATCHER_AND_AUTHORIZATION",
    changes: [],
    estimatedDuration: "fixture",
    mutations: [],
    installedDispatcherSha256: "a".repeat(64),
  };
}

function presenter(): SetupPresenter {
  return { plan: () => undefined, step: () => undefined, progress: () => undefined, heartbeatMs: () => 5000, cancellation: () => undefined, fingerprint: () => undefined, approve: async () => true, receipt: () => undefined };
}

function transaction(phase: SynchronizationPhase): RemoteSynchronizationTransaction {
  return {
    version: 1,
    transactionId: "a".repeat(32),
    phase,
    changeType: "DISPATCHER_AND_AUTHORIZATION",
    hostBindingSha256: "b".repeat(64),
    desiredGenerationIdentity: "c".repeat(64),
    previousGenerationIdentity: "d".repeat(64),
    previousGenerationAvailable: true,
    snapshotRoot: `/var/lib/opshaven/transactions/${"a".repeat(32)}/previous`,
    createdAt: "2026-08-01T17:00:00.000Z",
    updatedAt: "2026-08-01T17:00:00.000Z",
    integritySha256: "e".repeat(64),
  };
}

function dependencies(calls: Calls, options: { failStaged?: boolean; failActive?: boolean; failRollback?: boolean } = {}): RemoteSetupEngineDependencies {
  let currentPhase: SynchronizationPhase = "RECORD_PREVIOUS";
  return {
    preflight: async () => {
      calls.preflight += 1;
      return { ok: true, checkedAt: new Date().toISOString(), nodePath: "/usr/bin/node", remote: { platform: "Linux", distribution: "ubuntu", version: "24.04", architecture: "x86_64", nodePath: "/usr/bin/node", nodeVersion: "v22.0.0", freeBytes: 999999999, installation: { accountExists: true, runtimeExists: true, wrapperExists: true, configExists: true, receiptExists: true } }, checks: [] };
    },
    install: async () => {
      calls.runtimeInstall += 1;
      calls.dependencyInstall += 1;
      throw new Error("dispatcher-only scenario must not install runtime");
    },
    installDispatcher: async (_config, _desired, installedDigest, transactionId) => {
      calls.dispatcherInstall += 1;
      assert.equal(installedDigest, "a".repeat(64));
      assert.equal(transactionId, "a".repeat(32));
      return { ok: true, transactionId, dispatcherSha256: "3".repeat(64), runtimeTreeSha256: "f".repeat(64), changed: ["/usr/lib/opshaven/src/remote/dispatcher.js"], dependencyInstall: false };
    },
    trust: async () => { throw new Error("full runtime trust path must not run"); },
    synchronize: async () => {
      calls.synchronize += 1;
      return { ok: true, mode: "controlled", synchronizationKind: "authorization-sync", receiptId: "syncfixture", backupRoot: "/var/lib/opshaven/backups/syncfixture", dispatcherSha256: "3".repeat(64), capabilitySha256: "5".repeat(64), declarationSha256: "6".repeat(64), bindingSha256: "7".repeat(64), responsePublicKeySha256: "8".repeat(64), expiresAt: "2026-08-01T18:00:00.000Z", installedPaths: [], changed: ["/etc/opshaven/config.json.capability.json"] };
    },
    certify: async () => {
      calls.certify += 1;
      if (options.failActive && calls.certify === 1) throw new OpsHavenError("POLICY_DENIED", "fixture active verification failed");
      return { ok: true, certifiedAt: new Date().toISOString(), boundarySha256: "9".repeat(64), assertions: [] };
    },
    rollback: async () => { throw new Error("legacy rollback must not run"); },
    desired: async () => desired(),
    readiness: async () => compatible(),
    verifyReadiness: async () => compatible(),
    beginTransaction: async () => transaction("RECORD_PREVIOUS"),
    advanceTransaction: async (_config, _transactionId, phase) => {
      if (options.failStaged && phase === "VERIFY_STAGED") throw new OpsHavenError("POLICY_DENIED", "fixture staged verification failed");
      currentPhase = phase;
      return transaction(currentPhase);
    },
    rollbackTransaction: async (_config, transactionId) => {
      calls.rollback += 1;
      if (options.failRollback) throw new OpsHavenError("POLICY_DENIED", "fixture previous receipt mismatch");
      return { ok: true, transactionId, phase: "ROLLBACK_COMMIT", restoredGenerationIdentity: "d".repeat(64), restored: ["/usr/lib/opshaven"], removed: [] };
    },
  };
}

function zero(): Calls { return { preflight: 0, runtimeInstall: 0, dispatcherInstall: 0, dependencyInstall: 0, synchronize: 0, certify: 0, rollback: 0 }; }

async function run(options: { failStaged?: boolean; failActive?: boolean; failRollback?: boolean } = {}): Promise<{ calls: Calls; execute: Promise<unknown>; root: string }> {
  const value = await fixture();
  const calls = zero();
  const execute = executeRemoteSetup(value.config, plan(), { approved: true, nonInteractive: true, tui: false, json: true, presenter: presenter(), dependencies: dependencies(calls, options) });
  return { calls, execute, root: value.root };
}

test("failure before activation leaves the previous generation active without rollback", async () => {
  const scenario = await run({ failStaged: true });
  try {
    await assert.rejects(scenario.execute, (error: unknown) => error instanceof OpsHavenError && error.safeDetails?.setupOutcome === "SETUP_FAILED_NO_MUTATION" && error.safeDetails?.mutationStarted === false);
    assert.equal(scenario.calls.dispatcherInstall, 0);
    assert.equal(scenario.calls.rollback, 0);
  } finally { await fs.rm(scenario.root, { recursive: true, force: true }); }
});

test("failure after activation restores and verifies the previous generation", async () => {
  const scenario = await run({ failActive: true });
  try {
    await assert.rejects(scenario.execute, (error: unknown) => error instanceof OpsHavenError && error.safeDetails?.setupOutcome === "SETUP_FAILED_ROLLED_BACK" && error.safeDetails?.rollbackCompleted === true && error.safeDetails?.activeGeneration === "d".repeat(64));
    assert.equal(scenario.calls.dispatcherInstall, 1);
    assert.equal(scenario.calls.synchronize, 1);
    assert.equal(scenario.calls.rollback, 1);
    assert.equal(scenario.calls.certify, 2, "active and restored generations must both be checked");
  } finally { await fs.rm(scenario.root, { recursive: true, force: true }); }
});

test("rollback failure records an uncertain blocked state without raw traceback", async () => {
  const scenario = await run({ failActive: true, failRollback: true });
  try {
    await assert.rejects(scenario.execute, (error: unknown) => {
      if (!(error instanceof OpsHavenError)) return false;
      assert.equal(error.safeDetails?.setupOutcome, "SETUP_FAILED_ROLLBACK_FAILED");
      assert.equal(error.safeDetails?.rollbackCompleted, false);
      assert.equal(error.safeDetails?.safeNextCommand, "opshaven setup repair");
      assert.deepEqual(error.safeDetails?.blockedOperations, ["deployment planning", "deployment apply", "remote setup success certification"]);
      assert.doesNotMatch(error.message, /Traceback|RuntimeError|at .*\.ts:/);
      return true;
    });
  } finally { await fs.rm(scenario.root, { recursive: true, force: true }); }
});

test("successful dispatcher synchronization reuses runtime and installs no dependencies", async () => {
  const scenario = await run();
  try {
    const receipt = await scenario.execute as Awaited<ReturnType<typeof executeRemoteSetup>>;
    assert.equal(receipt.outcome, "SETUP_SUCCEEDED");
    assert.equal(receipt.changeType, "DISPATCHER_AND_AUTHORIZATION");
    assert.equal(receipt.installation, undefined);
    assert.equal(receipt.dispatcherInstallation?.dependencyInstall, false);
    assert.equal(scenario.calls.runtimeInstall, 0);
    assert.equal(scenario.calls.dependencyInstall, 0);
    assert.equal(scenario.calls.dispatcherInstall, 1);
    assert.equal(scenario.calls.synchronize, 1);
  } finally { await fs.rm(scenario.root, { recursive: true, force: true }); }
});
