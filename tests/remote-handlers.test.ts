import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "../src/config.js";
import { handleInspection } from "../src/remote/handlers.js";
import type { CommandRunner } from "../src/remote/runner.js";

const config = parseConfig({
  version: 1, policyVersion: "v1", limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
  audit: { path: "/var/lib/opshaven/audit.jsonl" }, approvals: { directory: "/var/lib/opshaven/approvals", secretFile: "/var/lib/opshaven/key", signingPrivateKeyFile: "/var/lib/opshaven/private.pem", verificationPublicKeyFile: "/etc/opshaven/public.pem", remoteUsedDirectory: "/var/lib/opshaven/remote-used", defaultTtlSeconds: 300 }, secretFingerprints: [],
  resources: [
    { id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/key", connectTimeoutMs: 5000 },
    { id: "svc.web", kind: "service", hostId: "host.main", unit: "example.service" },
  ],
});
const runner: CommandRunner = { async run(executable, args) {
  assert.equal(executable, "/usr/bin/systemctl");
  assert.deepEqual(args.slice(0, 2), ["show", "example.service"]);
  return { exitCode: 0, stdout: "Id=example.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\nExecMainStatus=0\nActiveEnterTimestamp=now\n" };
} };

test("remote handler resolves configured service unit", async () => {
  const data = await handleInspection({ config, runner }, { version: 1, requestId: "req-1", operation: "get_service_status", resourceId: "svc.web", args: { resourceId: "svc.web" }, limits: config.limits });
  assert.equal(data.activeState, "active");
  assert.equal(data.mainPid, 42);
});
