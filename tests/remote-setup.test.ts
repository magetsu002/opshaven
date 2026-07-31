import assert from "node:assert/strict";
import test from "node:test";
import { buildRemoteSetupPlan, parseRemoteSetupConfig } from "../src/setup/remote.js";

function fixture(): unknown {
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
  const unsafe = fixture() as any;
  unsafe.remote.runtimeRoot = "/opt/opshaven";
  assert.throws(() => parseRemoteSetupConfig(unsafe), /remote\.runtimeRoot/);
  const traversal = fixture() as any;
  traversal.local.runtimeRoot = "/workspace/../secret";
  assert.throws(() => parseRemoteSetupConfig(traversal), /normalized absolute path/);
  const account = fixture() as any;
  account.remote.account = "root";
  assert.throws(() => parseRemoteSetupConfig(account), /remote\.account/);
});
