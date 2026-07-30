import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import test from "node:test";
import { parseConfig } from "../src/config.js";
import { dispatchReadOnlyEnvelope } from "../src/remote/read-only-dispatcher.js";
import type { CommandRunner } from "../src/remote/runner.js";

const config = parseConfig({
  version: 1,
  policyVersion: "v1",
  limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
  audit: { path: "/var/lib/opshaven/audit.jsonl" },
  approvals: {
    directory: "/var/lib/opshaven/approvals",
    secretFile: "/var/lib/opshaven/approval.key",
    signingPrivateKeyFile: "/var/lib/opshaven/approval-private.pem",
    verificationPublicKeyFile: "/etc/opshaven/approval-public.pem",
    remoteUsedDirectory: "/var/lib/opshaven/remote-used",
    defaultTtlSeconds: 300,
  },
  secretFingerprints: [],
  resources: [
    {
      id: "host.main",
      kind: "host",
      address: "example.internal",
      port: 22,
      user: "opshaven",
      knownHostsFile: "/etc/opshaven/known_hosts",
      identityFile: "/etc/opshaven/id_ed25519",
      connectTimeoutMs: 5000,
    },
    { id: "svc.web", kind: "service", hostId: "host.main", unit: "example.service" },
    { id: "ctr.web", kind: "container", hostId: "host.main", runtime: "docker", container: "example" },
  ],
});

function envelope(operation: string, resourceId: string): string {
  return `${JSON.stringify({
    version: 1,
    requestId: "request-1",
    operation,
    resourceId,
    args: { resourceId, dryRun: false },
    limits: config.limits,
  })}\n`;
}

test("read-only dispatcher does not expose mutation operations", async () => {
  let calls = 0;
  const runner: CommandRunner = {
    async run() {
      calls += 1;
      return { stdout: "", exitCode: 0 };
    },
  };
  for (const operation of ["restart_service", "deploy_commit", "rollback_deployment"]) {
    const response = await dispatchReadOnlyEnvelope(config, envelope(operation, "svc.web"), runner);
    assert.equal(response.ok, false);
    if (!response.ok) assert.equal(response.error.code, "REMOTE_PROTOCOL_INVALID");
  }
  assert.equal(calls, 0);
});

test("read-only dispatcher does not expose container socket operations", async () => {
  let calls = 0;
  const runner: CommandRunner = {
    async run() {
      calls += 1;
      return { stdout: "", exitCode: 0 };
    },
  };
  const response = await dispatchReadOnlyEnvelope(config, envelope("get_container_status", "ctr.web"), runner);
  assert.equal(response.ok, false);
  if (!response.ok) assert.equal(response.error.code, "REMOTE_PROTOCOL_INVALID");
  assert.equal(calls, 0);
});

test("read-only dispatcher executes an allowlisted inspection", async () => {
  const runner: CommandRunner = {
    async run(executable) {
      assert.equal(executable, "/usr/bin/systemctl");
      return {
        stdout: "Id=example.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\nExecMainStatus=0\nActiveEnterTimestamp=now\n",
        exitCode: 0,
      };
    },
  };
  const raw = `${JSON.stringify({
    version: 1,
    requestId: "request-2",
    operation: "get_service_status",
    resourceId: "svc.web",
    args: { resourceId: "svc.web" },
    limits: config.limits,
  })}\n`;
  const response = await dispatchReadOnlyEnvelope(config, raw, runner);
  assert.equal(response.ok, true);
  if (response.ok) assert.equal(response.data.activeState, "active");
});

test("read-only source graph contains no privileged handler imports", async () => {
  const files = [
    "src/remote/read-only-dispatcher.ts",
    "src/remote/read-only-protocol.ts",
    "src/remote/read-only-policy.ts",
    "src/remote/read-only-handlers.ts",
  ];
  for (const file of files) {
    const source = await fs.readFile(file, "utf8");
    assert.doesNotMatch(source, /(?:mutations|authorization|approval|sudo|docker)/i, file);
  }
});
