import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { parseConfig, type OpsHavenConfig } from "../src/config.js";
import {
  DEPLOYMENT_MINIMUM_DISK_BYTES,
  DeploymentCoordinator,
  DeploymentPlanStore,
  validateExactRevision,
  type ApplicationRegistrationInput,
  type OperationClient,
} from "../src/deployment.js";
import { OpsHavenError } from "../src/errors.js";
import type { ResultEnvelope } from "../src/operations.js";

const CURRENT = "1".repeat(40);
const TARGET = "2".repeat(40);
const CHANGED = "3".repeat(40);

function success(operation: string, data: Record<string, unknown>, mutation = false): ResultEnvelope {
  const now = new Date(0).toISOString();
  return {
    ok: true,
    requestId: `request-${operation}`,
    operation,
    data,
    meta: {
      startedAt: now,
      finishedAt: now,
      dryRun: !mutation,
      mutation,
      truncated: false,
      redactions: 0,
      auditRecorded: true,
    },
  };
}

function failure(operation: string, message: string): ResultEnvelope {
  const now = new Date(0).toISOString();
  return {
    ok: false,
    requestId: `request-${operation}`,
    operation,
    error: { code: "REMOTE_OPERATION_FAILED", message, retryable: false },
    meta: {
      startedAt: now,
      finishedAt: now,
      dryRun: false,
      mutation: true,
      truncated: false,
      redactions: 0,
      auditRecorded: true,
    },
  };
}

class SyntheticDeploymentClient implements OperationClient {
  currentRevision = CURRENT;
  activeReleaseId = "release-current";
  healthy = true;
  availableDiskBytes = 10 * 1024 * 1024 * 1024;
  serviceIdentifier = "sample-api.service";
  runtimeAvailable = true;
  mutationCalls = 0;
  rollbackCalls = 0;
  mode: "success" | "build-failure" | "health-failure" | "rollback-failure" = "success";

  async execute(operationName: string, argsInput: unknown, _approvalToken?: string): Promise<ResultEnvelope> {
    const args = argsInput as Record<string, unknown>;
    if (operationName === "get_deployed_commit") {
      return success(operationName, {
        activeCommit: this.currentRevision,
        activeReleaseId: this.activeReleaseId,
        sourceRepositoryCommit: CHANGED,
        dirty: false,
      });
    }
    if (operationName === "get_service_status") {
      return success(operationName, {
        unit: this.serviceIdentifier,
        activeState: "active",
        subState: "running",
        exitStatus: 0,
      });
    }
    if (operationName === "run_health_probe") {
      return success(operationName, {
        reachable: true,
        expected: this.healthy,
        statusCode: this.healthy ? 200 : 503,
      });
    }
    if (operationName === "get_host_summary") {
      return success(operationName, {
        uname: this.runtimeAvailable ? "Linux synthetic 6.0 x86_64 GNU/Linux" : "",
        rootFilesystem: `/dev/synthetic 20000000 1000 ${Math.floor(this.availableDiskBytes / 1024)} 1% /`,
      });
    }
    if (operationName === "deploy_commit" && args.dryRun === true) {
      return success(operationName, { changed: false, plan: { commit: args.commit } });
    }
    if (operationName === "deploy_commit") {
      this.mutationCalls += 1;
      if (this.mode === "build-failure") return failure(operationName, "Build failed before activation.");
      this.currentRevision = String(args.commit);
      this.activeReleaseId = `release-${this.currentRevision.slice(0, 12)}`;
      if (this.mode === "health-failure" || this.mode === "rollback-failure") this.healthy = false;
      return success(operationName, { changed: true, commit: this.currentRevision }, true);
    }
    if (operationName === "rollback_deployment") {
      this.rollbackCalls += 1;
      if (this.mode === "rollback-failure") return failure(operationName, "Rollback failed safely.");
      this.currentRevision = CURRENT;
      this.activeReleaseId = "release-current";
      this.healthy = true;
      return success(operationName, { changed: true, commit: CURRENT }, true);
    }
    return failure(operationName, "Unsupported synthetic operation.");
  }

  async createApproval(): Promise<{ token: string; digest: string; expiresAt: string; operationDigest: string }> {
    return {
      token: "synthetic-exact-plan-approval",
      digest: "a".repeat(64),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      operationDigest: "b".repeat(64),
    };
  }
}

interface Fixture {
  root: string;
  configPath: string;
  stateRoot: string;
  config: OpsHavenConfig;
  client: SyntheticDeploymentClient;
  coordinator: DeploymentCoordinator;
  input: ApplicationRegistrationInput;
  advance(ms: number): void;
}

async function fixture(): Promise<Fixture> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-deployment-plan-"));
  const configPath = path.join(root, "config.json");
  const dispatcherPath = `${configPath}.dispatcher.json`;
  const stateRoot = path.join(root, "deployment-state");
  const knownHosts = path.join(root, "known_hosts");
  const identity = path.join(root, "restricted-ssh");
  const publicKey = path.join(root, "operator-public.pem");
  const privateKey = path.join(root, "operator-private.pem");
  const approvalSecret = path.join(root, "approval-secret");
  await fs.writeFile(knownHosts, "example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISynthetic\n", { mode: 0o600 });
  await fs.writeFile(identity, "synthetic-private-identity\n", { mode: 0o600 });
  await fs.writeFile(publicKey, "synthetic-public-verification-key\n", { mode: 0o600 });
  await fs.writeFile(privateKey, "synthetic-private-signing-key\n", { mode: 0o600 });
  await fs.writeFile(approvalSecret, "synthetic-approval-secret-32-bytes!!\n", { mode: 0o600 });
  const document = {
    version: 1,
    policyVersion: "v1",
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    audit: { path: path.join(root, "audit.jsonl") },
    approvals: {
      directory: path.join(root, "approvals"),
      secretFile: approvalSecret,
      signingPrivateKeyFile: privateKey,
      verificationPublicKeyFile: publicKey,
      remoteUsedDirectory: path.join(root, "remote-used"),
      defaultTtlSeconds: 300,
    },
    secretFingerprints: [],
    resources: [{
      id: "host.primary",
      kind: "host",
      address: "example.invalid",
      port: 22,
      user: "opshaven",
      knownHostsFile: knownHosts,
      identityFile: identity,
      connectTimeoutMs: 5000,
    }],
  };
  await fs.writeFile(configPath, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600 });
  await fs.writeFile(dispatcherPath, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600 });
  const config = parseConfig(document);
  const client = new SyntheticDeploymentClient();
  let now = Date.parse("2026-08-01T00:00:00.000Z");
  const coordinator = new DeploymentCoordinator(config, configPath, {
    root: stateRoot,
    client,
    now: () => now,
    nonce: () => "c".repeat(32),
  });
  const input: ApplicationRegistrationInput = {
    id: "sample-api",
    name: "Sample API",
    remoteTarget: "host.primary",
    repositoryLocation: path.join(root, "sample-api", "repository"),
    releaseLocation: path.join(root, "sample-api", "releases"),
    serviceIdentifier: "sample-api.service",
    healthCheckUrl: "http://127.0.0.1:3000/health",
    expectedStatus: 200,
  };
  return { root, configPath, stateRoot, config, client, coordinator, input, advance: (ms: number) => { now += ms; } };
}

async function registeredFixture(): Promise<Fixture> {
  const value = await fixture();
  await value.coordinator.registerApplication(value.input);
  value.config = await import("../src/config.js").then(({ loadConfig }) => loadConfig(value.configPath));
  value.coordinator = new DeploymentCoordinator(value.config, value.configPath, {
    root: value.stateRoot,
    client: value.client,
    now: () => Date.parse("2026-08-01T00:00:00.000Z"),
    nonce: () => "c".repeat(32),
  });
  return value;
}

test("exact revision validation rejects mutable and abbreviated references", () => {
  assert.equal(validateExactRevision(TARGET.toUpperCase()), TARGET);
  for (const invalid of ["main", "master", "latest", "HEAD", "v1.2.3", TARGET.slice(0, 12), "refs/heads/main"]) {
    assert.throws(() => validateExactRevision(invalid), (error: unknown) => error instanceof OpsHavenError && error.code === "INVALID_ARGUMENTS");
  }
});

test("application registration is atomic, narrow, and duplicate-safe", async () => {
  const value = await fixture();
  const before = await fs.readFile(value.configPath, "utf8");
  await assert.rejects(value.coordinator.registerApplication({ ...value.input, repositoryLocation: "/srv/../escape" }), OpsHavenError);
  assert.equal(await fs.readFile(value.configPath, "utf8"), before);
  await assert.rejects(value.coordinator.registerApplication({ ...value.input, serviceIdentifier: "sample-api.service;shutdown" }), OpsHavenError);
  assert.equal(await fs.readFile(value.configPath, "utf8"), before);
  const app = await value.coordinator.registerApplication(value.input);
  assert.equal(app.id, "sample-api");
  assert.equal(app.buildStrategy, "git-systemd-http-v1");
  const registered = await value.coordinator.registry.get("sample-api");
  assert.equal(registered.resourceBindingDigest, app.resourceBindingDigest);
  const after = await fs.readFile(value.configPath, "utf8");
  await assert.rejects(value.coordinator.registerApplication(value.input), (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED");
  assert.equal(await fs.readFile(value.configPath, "utf8"), after);
});

test("planning is read-only and returns the same immutable digest for unchanged inputs", async () => {
  const value = await registeredFixture();
  const first = await value.coordinator.createPlan("sample-api", TARGET);
  const second = await value.coordinator.createPlan("sample-api", TARGET);
  assert.equal(first.planId, second.planId);
  assert.equal(first.plan.targetRevision, TARGET);
  assert.equal(first.plan.currentRevision, CURRENT);
  assert.equal(first.plan.operations[0]?.kind, "verify_revision");
  assert.equal(first.plan.operations.at(-1)?.kind, "confirm_revision");
  assert.equal(value.client.mutationCalls, 0);
});

test("volatile disk drift preserves exact-plan identity and apply succeeds", async () => {
  const value = await registeredFixture();
  value.client.availableDiskBytes = 10 * 1024 * 1024 * 1024;
  const stored = await value.coordinator.createPlan("sample-api", TARGET);
  value.client.availableDiskBytes -= 100 * 1024 * 1024;
  const repeated = await value.coordinator.createPlan("sample-api", TARGET);
  assert.equal(repeated.planId, stored.planId);
  assert.equal(repeated.plan.observedStateFingerprint, stored.plan.observedStateFingerprint);
  const result = await value.coordinator.applyPlan(stored.planId, { approved: true });
  assert.equal(result.outcome, "DEPLOYMENT_SUCCEEDED");
  assert.equal(value.client.mutationCalls, 1);
});

test("insufficient apply-time disk fails before deployment mutation", async () => {
  const value = await registeredFixture();
  const stored = await value.coordinator.createPlan("sample-api", TARGET);
  value.client.availableDiskBytes = DEPLOYMENT_MINIMUM_DISK_BYTES - 1;
  await assert.rejects(
    value.coordinator.applyPlan(stored.planId, { approved: true }),
    (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED" && /disk space/i.test(error.message),
  );
  assert.equal(value.client.mutationCalls, 0);
});

test("service and runtime drift remain stale-plan blockers", async (t) => {
  await t.test("service identity", async () => {
    const value = await registeredFixture();
    const stored = await value.coordinator.createPlan("sample-api", TARGET);
    value.client.serviceIdentifier = "other.service";
    await assert.rejects(value.coordinator.applyPlan(stored.planId, { approved: true }), OpsHavenError);
    assert.equal(value.client.mutationCalls, 0);
  });
  await t.test("runtime readiness", async () => {
    const value = await registeredFixture();
    const stored = await value.coordinator.createPlan("sample-api", TARGET);
    value.client.runtimeAvailable = false;
    await assert.rejects(value.coordinator.applyPlan(stored.planId, { approved: true }), OpsHavenError);
    assert.equal(value.client.mutationCalls, 0);
  });
});

test("changed observed state produces a different plan identity", async () => {
  const value = await registeredFixture();
  const first = await value.coordinator.createPlan("sample-api", TARGET);
  value.client.currentRevision = CHANGED;
  value.client.activeReleaseId = "release-changed";
  const second = await value.coordinator.createPlan("sample-api", TARGET);
  assert.notEqual(first.planId, second.planId);
  assert.notEqual(first.plan.observedStateFingerprint, second.plan.observedStateFingerprint);
});

test("stored plan tampering is rejected by the plan digest", async () => {
  const value = await registeredFixture();
  const stored = await value.coordinator.createPlan("sample-api", TARGET);
  const digest = stored.planId.replace("sha256:", "");
  const file = path.join(value.stateRoot, "plans", `${digest}.json`);
  const document = JSON.parse(await fs.readFile(file, "utf8")) as { plan: { targetRevision: string } };
  document.plan.targetRevision = CHANGED;
  await fs.writeFile(file, `${JSON.stringify(document)}\n`, { mode: 0o600 });
  await assert.rejects(new DeploymentPlanStore(value.stateRoot).load(stored.planId), (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED");
});

test("exact stored plan applies once and replay is rejected", async () => {
  const value = await registeredFixture();
  const stored = await value.coordinator.createPlan("sample-api", TARGET);
  const result = await value.coordinator.applyPlan(stored.planId, { approved: true });
  assert.equal(result.outcome, "DEPLOYMENT_SUCCEEDED");
  assert.equal(result.activeRevision, TARGET);
  assert.equal(value.client.mutationCalls, 1);
  await assert.rejects(value.coordinator.applyPlan(stored.planId, { approved: true }), (error: unknown) => error instanceof OpsHavenError && error.code === "APPROVAL_REPLAYED");
  assert.equal(value.client.mutationCalls, 1);
});

test("stale remote state fails closed before mutation", async () => {
  const value = await registeredFixture();
  const stored = await value.coordinator.createPlan("sample-api", TARGET);
  value.client.currentRevision = CHANGED;
  value.client.activeReleaseId = "release-changed";
  await assert.rejects(value.coordinator.applyPlan(stored.planId, { approved: true }), (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED" && /stale/i.test(error.message));
  assert.equal(value.client.mutationCalls, 0);
});

test("expired plans fail closed before mutation", async () => {
  const value = await fixture();
  await value.coordinator.registerApplication(value.input);
  const config = await import("../src/config.js").then(({ loadConfig }) => loadConfig(value.configPath));
  const client = value.client;
  let now = Date.parse("2026-08-01T00:00:00.000Z");
  const coordinator = new DeploymentCoordinator(config, value.configPath, { root: value.stateRoot, client, now: () => now, nonce: () => "d".repeat(32) });
  const stored = await coordinator.createPlan("sample-api", TARGET);
  now += 16 * 60 * 1000;
  await assert.rejects(coordinator.applyPlan(stored.planId, { approved: true }), (error: unknown) => error instanceof OpsHavenError && error.code === "APPROVAL_EXPIRED");
  assert.equal(client.mutationCalls, 0);
});

test("health failure restores and verifies the previous release", async () => {
  const value = await registeredFixture();
  value.client.mode = "health-failure";
  const stored = await value.coordinator.createPlan("sample-api", TARGET);
  const result = await value.coordinator.applyPlan(stored.planId, { approved: true });
  assert.equal(result.outcome, "DEPLOYMENT_FAILED_ROLLED_BACK");
  assert.equal(result.activeRevision, CURRENT);
  assert.equal(result.rollbackAttempted, true);
  assert.equal(value.client.rollbackCalls, 1);
});

test("rollback failure is prominent and retains the application recovery lock", async () => {
  const value = await registeredFixture();
  value.client.mode = "rollback-failure";
  const stored = await value.coordinator.createPlan("sample-api", TARGET);
  const result = await value.coordinator.applyPlan(stored.planId, { approved: true });
  assert.equal(result.outcome, "DEPLOYMENT_FAILED_ROLLBACK_FAILED");
  const lock = new DeploymentPlanStore(value.stateRoot).lockFile("sample-api");
  const stat = await fs.lstat(lock);
  assert.equal(stat.isFile(), true);
});

test("persistent application lock rejects concurrent apply", async () => {
  const value = await registeredFixture();
  const stored = await value.coordinator.createPlan("sample-api", TARGET);
  const store = new DeploymentPlanStore(value.stateRoot);
  const release = await store.acquireApplicationLock("sample-api", { synthetic: true });
  await assert.rejects(value.coordinator.applyPlan(stored.planId, { approved: true }), (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED");
  assert.equal(value.client.mutationCalls, 0);
  await release();
});
