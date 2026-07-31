import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { preflightRemoteSetup, type PreflightRuntime } from "../src/setup/preflight.js";
import { buildRemoteSetupPlan, parseRemoteSetupConfig } from "../src/setup/remote.js";

function fixture(): any {
  return {
    version: 1,
    policyConfigPath: "/home/operator/.config/opshaven/config.json",
    expectedSourceSha: "0123456789abcdef0123456789abcdef01234567",
    target: {
      host: "vps.example.test",
      port: 22,
      adminUser: "ubuntu",
      knownHostsFile: "/home/operator/.config/opshaven/known_hosts",
      identityFile: "/home/operator/.ssh/id_ed25519",
      expectedHostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      privilege: "sudo-noninteractive",
    },
    local: {
      runtimeRoot: "/workspace/opshaven/dist-readonly",
      dispatcherPath: "/workspace/opshaven/dist-readonly/src/remote/read-only-dispatcher.js",
      wrapperTemplatePath: "/workspace/opshaven/packaging/opshaven-readonly-force-command",
      capabilityDeclarationPath: "/workspace/opshaven/security/capability-declaration.json",
      operatorPrivateKeyFile: "/home/operator/.config/opshaven/operator-private.pem",
      operatorPublicKeyFile: "/home/operator/.config/opshaven/operator-public.pem",
      restrictedAuthorizedKeyFile: "/home/operator/.ssh/opshaven.pub",
    },
    remote: {
      account: "opshaven",
      runtimeRoot: "/usr/lib/opshaven",
      configPath: "/etc/opshaven/config.json",
      wrapperPath: "/usr/local/bin/opshaven-readonly-force-command",
      stateDirectory: "/var/lib/opshaven",
      receiptPath: "/var/lib/opshaven/setup-receipt.json",
      nodeCandidates: ["/usr/bin/node", "/usr/local/bin/node"],
    },
    trust: { expiresInSeconds: 86400 },
  };
}

test("remote setup plan is deterministic and contains exact reviewed mutations", () => {
  const config = parseRemoteSetupConfig(fixture());
  const first = buildRemoteSetupPlan(config);
  const second = buildRemoteSetupPlan(config);
  assert.deepEqual(first, second);
  assert.equal(first.sourceSha, "0123456789abcdef0123456789abcdef01234567");
  assert.equal(first.mutations.some((item) => item.path === "/usr/lib/opshaven" && item.action === "replace"), true);
  assert.equal(first.mutations.some((item) => item.path === "/home/opshaven/.ssh/authorized_keys"), true);
  assert.equal(first.mutations.some((item) => item.path.endsWith("response-private.pem") && item.scope === "remote"), true);
  assert.equal(first.mutations.some((item) => item.path.includes("operator-private")), false);
  assert.equal(first.mutations.some((item) => item.path.includes("id_ed25519") && item.scope === "remote"), false);
});

test("remote setup schema rejects unsafe paths and authority changes", () => {
  const unsafe = fixture();
  unsafe.remote.runtimeRoot = "/opt/opshaven";
  assert.throws(() => parseRemoteSetupConfig(unsafe), /remote\.runtimeRoot/);
  const traversal = fixture();
  traversal.local.runtimeRoot = "/workspace/../secret";
  assert.throws(() => parseRemoteSetupConfig(traversal), /normalized absolute path/);
  const account = fixture();
  account.remote.account = "root";
  assert.throws(() => parseRemoteSetupConfig(account), /remote\.account/);
});

function preflightRuntime(configValue: ReturnType<typeof parseRemoteSetupConfig>, fingerprint = configValue.target.expectedHostKeySha256): PreflightRuntime {
  const pair = generateKeyPairSync("ed25519");
  const privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" });
  const publicPem = pair.publicKey.export({ type: "spki", format: "pem" });
  const files = new Map<string, Uint8Array>([
    [configValue.local.operatorPrivateKeyFile, Buffer.from(String(privatePem))],
    [configValue.local.operatorPublicKeyFile, Buffer.from(String(publicPem))],
  ]);
  const remoteFacts = JSON.stringify({
    platform: "Linux",
    distribution: "ubuntu",
    version: "26.04",
    architecture: "x86_64",
    nodePath: "/usr/bin/node",
    nodeVersion: "v22.23.1",
    freeBytes: 536870912,
    installation: { accountExists: false, runtimeExists: false, wrapperExists: false, configExists: false, receiptExists: false },
  });
  return {
    remote: {
      run: async () => ({ code: 0, stdout: "", stderr: "" }),
      runPrivileged: async () => ({ code: 0, stdout: "0\n", stderr: "" }),
      runPython: async () => ({ code: 0, stdout: remoteFacts, stderr: "" }),
      upload: async () => ({ code: 0, stdout: "", stderr: "" }),
      download: async () => ({ code: 0, stdout: "", stderr: "" }),
    },
    runLocal: async (command) => {
      if (command === "/usr/bin/uname") return { code: 0, stdout: "Linux\n", stderr: "" };
      if (command === "/usr/bin/git") return { code: 0, stdout: `${configValue.expectedSourceSha}\n`, stderr: "" };
      if (command === "/usr/bin/ssh-keygen") return { code: 0, stdout: `256 ${fingerprint} host (ED25519)\n`, stderr: "" };
      return { code: 1, stdout: "", stderr: "unexpected command" };
    },
    readFile: async (filePath) => files.get(filePath) ?? Buffer.from("fixture"),
    lstat: async (filePath) => ({ isFile: () => true, isSymbolicLink: () => false, mode: filePath.includes("private") || filePath.endsWith("id_ed25519") || filePath.endsWith("config.json") ? 0o100600 : 0o100644 }),
  };
}

test("preflight verifies exact source, pinned host key, local keys, remote platform, Node, disk, and privilege", async () => {
  const config = parseRemoteSetupConfig(fixture());
  const report = await preflightRemoteSetup(config, preflightRuntime(config));
  assert.equal(report.ok, true);
  assert.equal(report.nodePath, "/usr/bin/node");
  assert.equal(report.remote?.installation.accountExists, false);
  assert.equal(report.checks.every((item) => item.state === "passed"), true);
});

test("preflight fails closed when the pinned fingerprint is not the reviewed value", async () => {
  const config = parseRemoteSetupConfig(fixture());
  const report = await preflightRemoteSetup(config, preflightRuntime(config, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"));
  assert.equal(report.ok, false);
  assert.equal(report.checks.find((item) => item.id === "host-key-fingerprint")?.state, "failed");
});

test("preflight rejects manipulated process output instead of treating a contained value as trusted", async () => {
  const config = parseRemoteSetupConfig(fixture());
  const runtime = preflightRuntime(config) as any;
  const original = runtime.runLocal;
  runtime.runLocal = async (command: string, args: readonly string[], cwd?: string) => {
    if (command === "/usr/bin/git") return { code: 0, stdout: `${config.expectedSourceSha} attacker-controlled-suffix\n`, stderr: "" };
    if (command === "/usr/bin/ssh-keygen") return { code: 0, stdout: `256 prefix${config.target.expectedHostKeySha256}suffix host (ED25519)\n`, stderr: "" };
    return await original(command, args, cwd);
  };
  const report = await preflightRemoteSetup(config, runtime);
  assert.equal(report.ok, false);
  assert.equal(report.checks.find((item: any) => item.id === "source-head")?.state, "failed");
  assert.equal(report.checks.find((item: any) => item.id === "host-key-fingerprint")?.state, "failed");
});
