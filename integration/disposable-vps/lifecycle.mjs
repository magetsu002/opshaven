#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

const [configPath, commitsPath] = process.argv.slice(2);
if (!configPath || !commitsPath) throw new Error("Usage: lifecycle.mjs <config> <commits>");
const commits = JSON.parse(readFileSync(commitsPath, "utf8"));

function cli(args) {
  const result = spawnSync(process.execPath, ["dist/src/cli.js", ...args, "--config", configPath], {
    encoding: "utf8",
    timeout: 30000,
  });
  if (result.status !== 0) throw new Error(`CLI failed: ${result.stderr || result.stdout}`);
  return JSON.parse(result.stdout);
}

class Client {
  constructor() {
    this.child = spawn(process.execPath, ["dist/src/index.js", "--config", configPath], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.lines = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    this.pending = [];
    this.lines.on("line", (line) => this.pending.shift()?.resolve(JSON.parse(line)));
    this.child.on("exit", (code) => {
      const error = new Error(`MCP server exited unexpectedly: ${code}`);
      while (this.pending.length) this.pending.shift().reject(error);
    });
    this.id = 0;
  }

  request(method, params) {
    const id = ++this.id;
    const response = new Promise((resolve, reject) => this.pending.push({ resolve, reject }));
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, ...(params ? { params } : {}) })}\n`);
    return Promise.race([
      response,
      new Promise((_, reject) => setTimeout(() => reject(new Error(`MCP request timed out: ${method}`)), 30000)),
    ]);
  }

  async call(name, args) {
    const response = await this.request("tools/call", { name, arguments: args });
    if (response.error) throw new Error(`JSON-RPC failure: ${JSON.stringify(response.error)}`);
    return response.result.structuredContent;
  }

  close() {
    this.child.stdin.end();
  }
}

function approvalDeploy(commit, expectedCurrent) {
  return cli([
    "approve-deploy",
    "--resource", "dep.fixture",
    "--commit", commit,
    "--expected-current", expectedCurrent,
  ]).approvalToken;
}

function approvalRollback(releaseId) {
  return cli([
    "approve-rollback",
    "--resource", "dep.fixture",
    "--release", releaseId,
  ]).approvalToken;
}

function requireOk(result, label) {
  assert.equal(result.ok, true, `${label}: ${JSON.stringify(result.error)}`);
  return result.data;
}

function requireDenied(result, label) {
  assert.equal(result.ok, false, `${label} unexpectedly succeeded`);
  assert.match(result.error?.code ?? "", /^(?:APPROVAL_|REMOTE_OPERATION_FAILED|POLICY_DENIED)/, label);
}

const client = new Client();
try {
  const initialized = await client.request("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "opshaven-lifecycle", version: "1" },
  });
  assert.equal(initialized.result.serverInfo.name, "opshaven");

  const initial = requireOk(await client.call("get_deployed_commit", { resourceId: "dep.fixture" }), "initial state");
  assert.equal(initial.activeCommit, commits.a);
  assert.equal(initial.activeReleaseId, "release-initial");

  const dryRun = requireOk(await client.call("deploy_commit", {
    resourceId: "dep.fixture",
    commit: commits.b,
    expectedCurrentCommit: commits.a,
    dryRun: true,
  }), "deployment dry-run");
  assert.equal(dryRun.changed, false);
  assert.equal(dryRun.plan.commit, commits.b);
  const afterDryRun = requireOk(await client.call("get_deployed_commit", { resourceId: "dep.fixture" }), "state after dry-run");
  assert.equal(afterDryRun.activeCommit, commits.a);

  const mutationToken = approvalDeploy(commits.b, commits.a);
  const modified = await client.call("deploy_commit", {
    resourceId: "dep.fixture",
    commit: commits.c,
    expectedCurrentCommit: commits.a,
    dryRun: false,
    approvalToken: mutationToken,
  });
  requireDenied(modified, "modified approval arguments");

  const deployToken = approvalDeploy(commits.b, commits.a);
  const deployed = requireOk(await client.call("deploy_commit", {
    resourceId: "dep.fixture",
    commit: commits.b,
    expectedCurrentCommit: commits.a,
    dryRun: false,
    approvalToken: deployToken,
  }), "exact deployment");
  assert.equal(deployed.commit, commits.b);
  assert.equal(deployed.healthVerified, true);

  const activeB = requireOk(await client.call("get_deployed_commit", { resourceId: "dep.fixture" }), "deployed state");
  assert.equal(activeB.activeCommit, commits.b);
  const serviceB = requireOk(await client.call("get_service_status", { resourceId: "svc.fixture" }), "service activation");
  assert.equal(serviceB.activeState, "active");
  const probeB = requireOk(await client.call("run_health_probe", { resourceId: "probe.fixture" }), "deployment probe");
  assert.equal(probeB.expected, true);

  const replay = await client.call("deploy_commit", {
    resourceId: "dep.fixture",
    commit: commits.b,
    expectedCurrentCommit: commits.a,
    dryRun: false,
    approvalToken: deployToken,
  });
  requireDenied(replay, "approval replay");

  const unhealthyToken = approvalDeploy(commits.c, commits.b);
  const unhealthy = await client.call("deploy_commit", {
    resourceId: "dep.fixture",
    commit: commits.c,
    expectedCurrentCommit: commits.b,
    dryRun: false,
    approvalToken: unhealthyToken,
  });
  requireDenied(unhealthy, "failed health verification");
  const restoredB = requireOk(await client.call("get_deployed_commit", { resourceId: "dep.fixture" }), "restored deployment");
  assert.equal(restoredB.activeCommit, commits.b);
  const restoredProbe = requireOk(await client.call("run_health_probe", { resourceId: "probe.fixture" }), "restored health");
  assert.equal(restoredProbe.expected, true);

  const rollbackToken = approvalRollback("release-initial");
  const rollback = requireOk(await client.call("rollback_deployment", {
    resourceId: "dep.fixture",
    releaseId: "release-initial",
    dryRun: false,
    approvalToken: rollbackToken,
  }), "recorded rollback");
  assert.equal(rollback.commit, commits.a);
  assert.equal(rollback.healthVerified, true);
  const activeA = requireOk(await client.call("get_deployed_commit", { resourceId: "dep.fixture" }), "rolled-back state");
  assert.equal(activeA.activeCommit, commits.a);
  const serviceA = requireOk(await client.call("get_service_status", { resourceId: "svc.fixture" }), "rolled-back service");
  assert.equal(serviceA.activeState, "active");

  const audit = cli(["verify-audit"]);
  assert.equal(audit.valid, true);
  assert.ok(audit.records >= 12, `expected lifecycle audit records, received ${audit.records}`);

  process.stdout.write(JSON.stringify({
    dryRun: "no-change",
    deployed: commits.b,
    failedHealthRestored: commits.b,
    rolledBack: commits.a,
    replayRejected: true,
    argumentMutationRejected: true,
    auditRecords: audit.records,
  }) + "\n");
} finally {
  client.close();
}
