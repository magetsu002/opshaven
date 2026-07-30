import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import type { HostConfig } from "../src/config/schema.js";
import { OpsHavenError } from "../src/core/errors.js";
import type { ResolvedOperation } from "../src/policy/operations.js";
import { resolveOperation } from "../src/policy/operations.js";
import { ApprovalVerifier, createApprovalRequest, signApprovalRequest } from "../src/security/approval.js";
import { parseConfig } from "../src/config/schema.js";
import { runProcess, type ProcessResult, type ProcessRunner } from "../src/transport/process.js";
import { RestrictedSshTransport } from "../src/transport/ssh.js";
import { readFile } from "node:fs/promises";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map(async (directory) => await rm(directory, { recursive: true, force: true })));
});

const host: HostConfig = {
  id: "fixture-host",
  address: "192.0.2.10",
  port: 22,
  username: "opshaven",
  identityFile: "/tmp/id",
  knownHostsFile: "/tmp/known_hosts",
  hostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  dispatcherCommand: "opshaven-dispatch",
  firewallProvider: "ufw"
};

const operation: ResolvedOperation = {
  requestId: "00000000-0000-4000-8000-000000000000",
  operation: "get_host_summary",
  kind: "read",
  target: "fixture-host",
  hostId: "fixture-host",
  args: { hostId: "fixture-host" },
  expectedState: {},
  policyVersion: "v1",
  timeoutMs: 1000,
  output: { maxBytes: 4096, maxLines: 20 },
  dryRun: false,
  requiresApproval: false
};

function result(exitCode: number, stdout: string, stderr = ""): ProcessResult {
  return { exitCode, stdout: Buffer.from(stdout), stderr: Buffer.from(stderr) };
}

function sshRunner(remoteOutput: string): ProcessRunner {
  let calls = 0;
  return async () => {
    calls += 1;
    if (calls === 1) return result(0, "host key line");
    if (calls === 2) return result(0, `256 ${host.hostKeySha256} host (ED25519)\n`);
    return result(0, remoteOutput);
  };
}

describe("adversarial security regressions", () => {
  it("rejects command-shaped IDs and unknown argument fields before transport", async () => {
    const config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
    for (const input of [
      { serviceId: "demo-service;id" },
      { serviceId: "demo-service", command: "id" },
      { serviceId: "../../etc/passwd" }
    ]) {
      assert.throws(() => resolveOperation(config, "get_service_status", input), OpsHavenError);
    }
  });

  it("rejects remote success and error envelopes with extra or malformed fields", async () => {
    const malformed = [
      { version: 1, requestId: operation.requestId, ok: true, data: {}, shell: "escaped" },
      { version: 1, requestId: operation.requestId, ok: false, error: { code: 7, message: "bad", retryable: false } },
      { version: 1, requestId: operation.requestId, ok: false, error: { code: "X", message: "bad", retryable: false, secret: "x" } }
    ];
    for (const value of malformed) {
      await assert.rejects(
        () => new RestrictedSshTransport(sshRunner(JSON.stringify(value))).execute(host, operation),
        (error: unknown) => error instanceof OpsHavenError && error.code === "REMOTE_PROTOCOL_ERROR"
      );
    }
  });

  it("enforces subprocess byte limits and timeouts", async () => {
    await assert.rejects(
      () => runProcess({
        executable: process.execPath,
        args: ["-e", "process.stdout.write('x'.repeat(10000))"],
        timeoutMs: 1000,
        output: { maxBytes: 256, maxLines: 10 }
      }),
      (error: unknown) => error instanceof OpsHavenError && error.code === "OUTPUT_LIMIT_EXCEEDED"
    );
    await assert.rejects(
      () => runProcess({
        executable: process.execPath,
        args: ["-e", "setTimeout(() => {}, 10000)"],
        timeoutMs: 25,
        output: { maxBytes: 256, maxLines: 10 }
      }),
      (error: unknown) => error instanceof OpsHavenError && error.code === "SSH_TIMEOUT"
    );
  });

  it("allows at most one winner during concurrent approval replay", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opshaven-approval-race-"));
    directories.push(directory);
    const mutation: ResolvedOperation = {
      ...operation,
      operation: "restart_service",
      kind: "mutation",
      target: "demo-service",
      args: { serviceId: "demo-service" },
      expectedState: { activeState: "active" },
      requiresApproval: true
    };
    const key = Buffer.from("k".repeat(64));
    const request = createApprovalRequest(
      mutation,
      300,
      () => new Date("2026-01-01T00:00:00.000Z"),
      "nonce-abcdefghijklmnop"
    );
    const token = signApprovalRequest(request, key);
    const verifier = new ApprovalVerifier(directory, key, () => new Date("2026-01-01T00:00:01.000Z"));
    const settled = await Promise.allSettled([
      verifier.verifyAndConsume(mutation, token),
      verifier.verifyAndConsume(mutation, token)
    ]);
    assert.equal(settled.filter((item) => item.status === "fulfilled").length, 1);
    assert.equal(settled.filter((item) => item.status === "rejected").length, 1);
  });
});
