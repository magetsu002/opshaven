import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { HostConfig } from "../src/config/schema.js";
import { OpsHavenError } from "../src/core/errors.js";
import type { ResolvedOperation } from "../src/policy/operations.js";
import { RestrictedSshTransport } from "../src/transport/ssh.js";
import type { ProcessRequest, ProcessResult, ProcessRunner } from "../src/transport/process.js";

const host: HostConfig = {
  id: "demo-host",
  address: "192.0.2.10",
  port: 22,
  username: "opshaven",
  identityFile: "/tmp/id",
  knownHostsFile: "/tmp/known_hosts",
  hostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  dispatcherCommand: "opshaven-dispatch"
};

const operation: ResolvedOperation = {
  requestId: "00000000-0000-4000-8000-000000000000",
  operation: "get_host_summary",
  kind: "read",
  target: "demo-host",
  hostId: "demo-host",
  args: { hostId: "demo-host" },
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

describe("restricted SSH transport", () => {
  it("uses a fixed no-PTY, no-forwarding command and strict known_hosts", async () => {
    const requests: ProcessRequest[] = [];
    const runner: ProcessRunner = async (request) => {
      requests.push(request);
      if (requests.length === 1) return result(0, "host key line");
      if (requests.length === 2) return result(0, `256 ${host.hostKeySha256} host (ED25519)\n`);
      return result(0, JSON.stringify({ version: 1, requestId: operation.requestId, ok: true, data: {} }));
    };
    const response = await new RestrictedSshTransport(runner).execute(host, operation);
    assert.equal(response.ok, true);
    const ssh = requests[2]!;
    assert.equal(ssh.executable, "/usr/bin/ssh");
    assert.ok(ssh.args.includes("-T"));
    assert.ok(ssh.args.includes("ClearAllForwardings=yes"));
    assert.ok(ssh.args.includes("StrictHostKeyChecking=yes"));
    assert.equal(ssh.args.at(-1), "opshaven-dispatch");
    assert.equal(ssh.args.filter((arg) => arg === "opshaven-dispatch").length, 1);
  });

  it("rejects host-key changes before connecting", async () => {
    let calls = 0;
    const runner: ProcessRunner = async () => {
      calls += 1;
      return calls === 1 ? result(0, "host key line") : result(0, "256 SHA256:wrong host\n");
    };
    await assert.rejects(() => new RestrictedSshTransport(runner).execute(host, operation), (error: unknown) => {
      assert.ok(error instanceof OpsHavenError);
      assert.equal(error.code, "SSH_HOST_KEY_MISMATCH");
      return true;
    });
    assert.equal(calls, 2);
  });

  it("rejects malformed, multiline, and binary remote output", async () => {
    const outputs = ["not-json", "{}\n{}", "\u0000"];
    for (const output of outputs) {
      let calls = 0;
      const runner: ProcessRunner = async () => {
        calls += 1;
        if (calls === 1) return result(0, "host key line");
        if (calls === 2) return result(0, `256 ${host.hostKeySha256} host\n`);
        return result(0, output);
      };
      await assert.rejects(() => new RestrictedSshTransport(runner).execute(host, operation), OpsHavenError);
    }
  });
});
