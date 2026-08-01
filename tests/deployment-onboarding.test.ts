import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { loadConfig, type OpsHavenConfig } from "../src/config.js";
import {
  DeploymentCoordinator,
  validateExactRevision,
  type ApplicationRegistrationInput,
  type DeploymentApplication,
  type OperationClient,
} from "../src/deployment.js";
import {
  renderApplicationRegistration,
  renderDeploymentApply,
  renderDeploymentFailure,
  type RegistrationNext,
} from "../src/deployment/command.js";
import { OpsHavenError } from "../src/errors.js";
import type { ResultEnvelope } from "../src/operations.js";

const CURRENT = process.env.OPSHAVEN_SAMPLE_CURRENT_REVISION ?? "1".repeat(40);
const TARGET = process.env.OPSHAVEN_SAMPLE_HEALTHY_REVISION ?? "2".repeat(40);

function success(operation: string, data: Record<string, unknown>, mutation = false): ResultEnvelope {
  const timestamp = new Date(0).toISOString();
  return {
    ok: true,
    requestId: `request-${operation}`,
    operation,
    data,
    meta: {
      startedAt: timestamp,
      finishedAt: timestamp,
      dryRun: !mutation,
      mutation,
      truncated: false,
      redactions: 0,
      auditRecorded: true,
    },
  };
}

class OnboardingClient implements OperationClient {
  currentRevision = CURRENT;
  sourceRevision = TARGET;
  dirty = false;
  verifyMembership = true;
  mutationCalls = 0;
  verificationCalls = 0;

  async execute(
    operationName: string,
    argsInput: unknown,
    _approvalToken?: string,
    _actor?: string,
  ): Promise<ResultEnvelope> {
    const args = argsInput as Record<string, unknown>;
    if (operationName === "get_deployed_commit") {
      return success(operationName, {
        activeCommit: this.currentRevision,
        activeReleaseId: `release-${this.currentRevision.slice(0, 12)}`,
        sourceRepositoryCommit: this.sourceRevision,
        dirty: this.dirty,
      });
    }
    if (operationName === "get_service_status") {
      return success(operationName, {
        unit: "sample-api.service",
        activeState: "active",
        subState: "running",
        exitStatus: 0,
      });
    }
    if (operationName === "run_health_probe") {
      return success(operationName, {
        reachable: true,
        expected: true,
        statusCode: 200,
      });
    }
    if (operationName === "get_host_summary") {
      return success(operationName, {
        uname: "Linux synthetic 6.0 x86_64 GNU/Linux",
        rootFilesystem: "/dev/synthetic 1000000 1000 999000 1% /",
      });
    }
    if (operationName === "deploy_commit" && args.dryRun === true) {
      this.verificationCalls += 1;
      const commit = String(args.commit ?? "");
      return success(operationName, {
        changed: false,
        plan: { commit: this.verifyMembership && commit === this.sourceRevision ? commit : "" },
      });
    }
    if (operationName === "deploy_commit") {
      this.mutationCalls += 1;
      this.currentRevision = String(args.commit);
      return success(operationName, { changed: true, commit: this.currentRevision }, true);
    }
    if (operationName === "rollback_deployment") {
      this.currentRevision = CURRENT;
      return success(operationName, { changed: true, commit: CURRENT }, true);
    }
    throw new Error(`Unexpected synthetic operation: ${operationName}`);
  }

  async createApproval(
    _operationName: string,
    _args: unknown,
    _ttlSeconds?: number,
  ): Promise<{ token: string; digest: string; expiresAt: string; operationDigest: string }> {
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
  client: OnboardingClient;
  coordinator: DeploymentCoordinator;
  input: ApplicationRegistrationInput;
}

async function fixture(): Promise<Fixture> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-deployment-onboarding-"));
  await fs.chmod(root, 0o700);
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
    policyVersion: "onboarding-v1",
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
  const config = await loadConfig(configPath);
  const client = new OnboardingClient();
  const coordinator = new DeploymentCoordinator(config, configPath, {
    root: stateRoot,
    now: () => Date.parse("2026-08-01T00:00:00.000Z"),
    nonce: () => "c".repeat(32),
    client,
  });
  const input: ApplicationRegistrationInput = {
    id: "sample-api",
    name: "Sample API",
    remoteTarget: "host.primary",
    repositoryLocation: "/srv/opshaven-fixtures/sample-api/repository",
    releaseLocation: "/srv/opshaven-fixtures/sample-api/releases",
    serviceIdentifier: "sample-api.service",
    healthCheckUrl: "http://127.0.0.1:3000/health",
    expectedStatus: 200,
  };
  return { root, configPath, stateRoot, config, client, coordinator, input };
}

async function registeredFixture(): Promise<Fixture & { application: DeploymentApplication }> {
  const value = await fixture();
  const application = await value.coordinator.registerApplication(value.input);
  value.config = await loadConfig(value.configPath);
  value.coordinator = new DeploymentCoordinator(value.config, value.configPath, {
    root: value.stateRoot,
    now: () => Date.parse("2026-08-01T00:00:00.000Z"),
    nonce: () => "c".repeat(32),
    client: value.client,
  });
  return { ...value, application };
}

function registrationNext(): RegistrationNext {
  return {
    kind: "plan",
    command: `opshaven deploy plan sample-api --revision ${TARGET}`,
    revision: TARGET,
    revisionLabel: "Recommended healthy sample revision",
  };
}

test("registration wizard contains self-guiding field explanations and distinct defaults", async () => {
  const compiled = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src/deployment/command.js");
  const source = await fs.readFile(compiled, "utf8");
  for (const text of [
    "Register a deployment application",
    "Press Enter at every prompt to use the sample safely.",
    "Application ID",
    "The permanent lowercase name used in OpsHaven commands.",
    "Application name",
    "The friendly label shown in reports and deployment output.",
    "The absolute path to the Git repository on the remote machine.",
    "The remote directory where versioned releases will be prepared.",
    "The approved systemd service OpsHaven may restart after activation.",
    "The approved HTTP endpoint used to verify a successful deployment.",
    "Sample API",
    "sample-api",
  ]) {
    assert.equal(source.includes(text), true, `missing onboarding copy: ${text}`);
  }
});

test("registration summary distinguishes the friendly name, stable ID, remote paths, and actual revision", async () => {
  const value = await registeredFixture();
  try {
    const output = renderApplicationRegistration(value.application, registrationNext(), false);
    assert.match(output, /✓ Application registered/);
    assert.match(output, /Name: Sample API/);
    assert.match(output, /ID: sample-api/);
    assert.match(output, /\/srv\/opshaven-fixtures\/sample-api\/repository/);
    assert.match(output, /Recommended healthy sample revision/);
    assert.match(output, new RegExp(TARGET));
    assert.match(output, new RegExp(`opshaven deploy plan sample-api --revision ${TARGET}`));
    assert.doesNotMatch(output, /\u001b\[/);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("guided revision discovery resolves one complete verified immutable SHA without mutation", async () => {
  const value = await registeredFixture();
  try {
    const choices = await value.coordinator.discoverRevisions("sample-api");
    assert.deepEqual(choices, [{
      revision: TARGET,
      label: "Recommended healthy sample revision",
      recommended: true,
    }]);
    assert.equal(validateExactRevision(choices[0]?.revision ?? ""), TARGET);
    assert.equal(value.client.verificationCalls, 1);
    assert.equal(value.client.mutationCalls, 0);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("clean-room beginner path registers, discovers, plans, applies, and verifies the exact revision", async () => {
  const value = await registeredFixture();
  try {
    const choices = await value.coordinator.discoverRevisions("sample-api");
    const selected = choices[0]?.revision;
    assert.equal(selected, TARGET);
    const stored = await value.coordinator.createPlan("sample-api", selected ?? "");
    assert.equal(stored.plan.targetRevision, TARGET);
    assert.equal(stored.plan.currentRevision, CURRENT);
    assert.match(stored.planId, /^sha256:[a-f0-9]{64}$/);
    assert.equal(value.client.mutationCalls, 0);
    const result = await value.coordinator.applyPlan(stored.planId, { approved: true });
    assert.equal(result.outcome, "DEPLOYMENT_SUCCEEDED");
    assert.equal(result.activeRevision, TARGET);
    assert.equal(result.healthVerified, true);
    assert.equal(value.client.mutationCalls, 1);
    const output = renderDeploymentApply(result, false);
    assert.match(output, /✓ Deployment succeeded/);
    assert.match(output, /✓ Health check passed/);
    assert.match(output, /✓ Target revision confirmed/);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("revision discovery fails closed for dirty, malformed, absent, or already-active revisions", async () => {
  const value = await registeredFixture();
  try {
    value.client.dirty = true;
    await assert.rejects(value.coordinator.discoverRevisions("sample-api"), /uncommitted changes/);
    value.client.dirty = false;
    value.client.sourceRevision = "main";
    await assert.rejects(value.coordinator.discoverRevisions("sample-api"), /complete Git commit SHA/);
    value.client.sourceRevision = TARGET;
    value.client.verifyMembership = false;
    await assert.rejects(value.coordinator.discoverRevisions("sample-api"), /not verified/);
    value.client.verifyMembership = true;
    value.client.currentRevision = TARGET;
    await assert.rejects(value.coordinator.discoverRevisions("sample-api"), /No different verified/);
    assert.equal(value.client.mutationCalls, 0);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("server fingerprints receive a specific explanation and guided next command", () => {
  const entered = "e/u2jieAZNlTcRa2WeW5nbeG9GApmrQ9lSrrYzdfjw4";
  const output = renderDeploymentFailure(
    new OpsHavenError("INVALID_ARGUMENTS", "Revision must be one complete 40-character Git commit SHA."),
    { operation: "plan", applicationId: "sample-api", revisionInput: entered },
    false,
  );
  assert.match(output, /looks like a server identity fingerprint/);
  assert.match(output, new RegExp(entered.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(output, /server, not application code/);
  assert.match(output, /opshaven deploy plan sample-api/);
  assert.match(output, /No changes were made/);
  assert.doesNotMatch(output, /opshaven doctor/);
});

test("missing, branch, tag, and abbreviated revisions remain blocked with syntax-specific guidance", () => {
  const values = ["", "main", "v1.2.3", TARGET.slice(0, 12)];
  for (const revisionInput of values) {
    const output = renderDeploymentFailure(
      new OpsHavenError("INVALID_ARGUMENTS", "Revision must be one complete 40-character Git commit SHA."),
      { operation: "plan", applicationId: "sample-api", revisionInput },
      false,
    );
    assert.match(output, /Deployment plan blocked/);
    assert.match(output, /40-character Git commit SHA/);
    assert.match(output, /opshaven deploy plan sample-api/);
    assert.doesNotMatch(output, /opshaven doctor/);
  }
});

test("doctor distinguishes registration, repository, and verified-revision readiness", async () => {
  const value = await registeredFixture();
  try {
    const report = await value.coordinator.deploymentDoctor();
    assert.equal(report.next, "opshaven deploy plan sample-api");
    assert.equal(report.checks.some((item) => item.label === "Sample API registered" && item.passed), true);
    assert.equal(report.checks.some((item) => item.label === "Sample API: repository available" && item.passed), true);
    assert.equal(report.checks.some((item) => item.label === "Sample API: verified revision available" && item.passed), true);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("shared deployment presentation supports color while plain and JSON output remain ANSI-free", async () => {
  const value = await registeredFixture();
  try {
    const plain = renderApplicationRegistration(value.application, registrationNext(), false);
    const colored = renderApplicationRegistration(value.application, registrationNext(), true);
    const failure = renderDeploymentFailure(
      new OpsHavenError("INVALID_ARGUMENTS", "Revision must be one complete 40-character Git commit SHA."),
      { operation: "plan", applicationId: "sample-api", revisionInput: "main" },
      true,
    );
    assert.doesNotMatch(plain, /\u001b\[/);
    assert.match(colored, /\u001b\[/);
    assert.match(failure, /\u001b\[/);
    const json = JSON.stringify({ ok: true, application: value.application, next: registrationNext() });
    assert.doesNotMatch(json, /\u001b\[/);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});
