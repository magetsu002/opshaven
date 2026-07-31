import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { buildRestrictedAuthorizedKey, buildRuntimeManifest, installRestrictedRuntime, renderReadonlyWrapper } from "../src/setup/install.js";
import type { RemoteSetupPreflightReport } from "../src/setup/preflight.js";
import { parseRemoteSetupConfig } from "../src/setup/remote.js";
import type { RemoteAdminTransport, SetupCommandResult, SetupProcessOptions } from "../src/setup/transport.js";

const runtimeFiles = [
  "src/capabilities.js",
  "src/capability-declaration.js",
  "src/config.js",
  "src/errors.js",
  "src/safe-fs.js",
  "src/remote/authenticated-protocol.js",
  "src/remote/confinement.js",
  "src/remote/read-only-dispatcher.js",
  "src/remote/read-only-handlers.js",
  "src/remote/read-only-policy.js",
  "src/remote/read-only-protocol.js",
  "src/remote/runner.js",
];

async function writeRuntime(root: string, omit?: string): Promise<void> {
  for (const file of runtimeFiles) {
    if (file === omit) continue;
    const destination = path.join(root, ...file.split("/"));
    await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await fs.writeFile(destination, `export const fixture = ${JSON.stringify(file)};\n`, { mode: 0o600 });
  }
}

function setupFixture(root: string): any {
  const policy = path.join(root, "config.json");
  return {
    version: 1,
    policyConfigPath: policy,
    expectedSourceSha: "0123456789abcdef0123456789abcdef01234567",
    target: {
      host: "vps.example.test",
      port: 22,
      adminUser: "ubuntu",
      knownHostsFile: path.join(root, "known_hosts"),
      identityFile: path.join(root, "admin_id"),
      expectedHostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      privilege: "sudo-noninteractive",
    },
    local: {
      runtimeRoot: path.join(root, "runtime"),
      dispatcherPath: path.join(root, "runtime/src/remote/read-only-dispatcher.js"),
      wrapperTemplatePath: path.join(root, "wrapper"),
      capabilityDeclarationPath: path.join(root, "declaration.json"),
      operatorPrivateKeyFile: path.join(root, "operator-private.pem"),
      operatorPublicKeyFile: path.join(root, "operator-public.pem"),
      restrictedAuthorizedKeyFile: path.join(root, "restricted.pub"),
    },
    remote: {
      account: "opshaven",
      runtimeRoot: "/usr/lib/opshaven",
      configPath: "/etc/opshaven/config.json",
      wrapperPath: "/usr/local/bin/opshaven-readonly-force-command",
      stateDirectory: "/var/lib/opshaven",
      receiptPath: "/var/lib/opshaven/setup-receipt.json",
      nodeCandidates: ["/usr/bin/node"],
    },
    trust: { expiresInSeconds: 86400 },
  };
}

function remotePolicy(root: string): unknown {
  return {
    version: 1,
    policyVersion: "setup-test",
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    audit: { path: "/var/lib/opshaven/audit.jsonl" },
    approvals: {
      directory: "/var/lib/opshaven/unused-approvals",
      secretFile: "/var/lib/opshaven/unused-secret",
      signingPrivateKeyFile: "/var/lib/opshaven/unused-private",
      verificationPublicKeyFile: "/etc/opshaven/approval-public.pem",
      remoteUsedDirectory: "/var/lib/opshaven/remote-used",
      defaultTtlSeconds: 300,
    },
    secretFingerprints: [],
    resources: [{ id: "host.main", kind: "host", address: "localhost", port: 22, user: "opshaven", knownHostsFile: path.join(root, "unused-known-hosts"), identityFile: path.join(root, "unused-identity"), connectTimeoutMs: 5000 }],
  };
}

class RecordingTransport implements RemoteAdminTransport {
  uploadedNames: string[] = [];
  treeHash = "";

  async run(): Promise<SetupCommandResult> { return { code: 0, stdout: "", stderr: "" }; }
  async runPython(): Promise<SetupCommandResult> { return { code: 0, stdout: "", stderr: "" }; }
  async download(): Promise<SetupCommandResult> { return { code: 0, stdout: "", stderr: "" }; }

  async upload(localPath: string): Promise<SetupCommandResult> {
    this.uploadedNames = await fs.readdir(localPath);
    const manifest = JSON.parse(await fs.readFile(path.join(localPath, "runtime-manifest.json"), "utf8")) as { treeSha256: string };
    this.treeHash = manifest.treeSha256;
    return { code: 0, stdout: "", stderr: "" };
  }

  async runPrivileged(_command: readonly string[], _options?: SetupProcessOptions): Promise<SetupCommandResult> {
    return { code: 0, stdout: JSON.stringify({ ok: true, changed: ["/usr/lib/opshaven"], runtimeTreeSha256: this.treeHash, backupRoot: "/var/lib/opshaven/backups/fixture" }), stderr: "" };
  }
}

test("runtime manifest requires the complete compiled read-only dependency tree", async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-runtime-manifest-"));
  try {
    await writeRuntime(root);
    const complete = await buildRuntimeManifest(root);
    assert.equal(complete.files.length, runtimeFiles.length);
    assert.match(complete.treeSha256, /^[a-f0-9]{64}$/);
    await fs.rm(root, { recursive: true, force: true });
    await fs.mkdir(root, { recursive: true, mode: 0o700 });
    await writeRuntime(root, "src/remote/read-only-handlers.js");
    await assert.rejects(buildRuntimeManifest(root), /runtime is incomplete/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("generated wrapper fixes Node and dispatcher paths without weakening confinement", () => {
  const template = "#!/bin/sh\nexec /usr/bin/setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all --reset-env /usr/bin/env PATH=/usr/bin:/bin /usr/bin/node /usr/lib/opshaven/read-only-dispatcher.js \"$@\"\n";
  const rendered = renderReadonlyWrapper(template, "/usr/local/bin/node", "/usr/lib/opshaven");
  assert.equal(rendered.includes("/usr/local/bin/node /usr/lib/opshaven/src/remote/read-only-dispatcher.js"), true);
  assert.equal(rendered.includes("--bounding-set"), false);
  for (const flag of ["--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--reset-env"]) assert.equal(rendered.includes(flag), true);
});

test("restricted authorized key forces the exact read-only wrapper and denies client command selection", () => {
  const result = buildRestrictedAuthorizedKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA fixture", "/usr/local/bin/opshaven-readonly-force-command", "/etc/opshaven/config.json");
  assert.equal(result.startsWith("restrict,command=\"/usr/local/bin/opshaven-readonly-force-command --config /etc/opshaven/config.json\" ssh-ed25519 "), true);
  assert.equal(result.includes("no-port-forwarding"), false);
  assert.throws(() => buildRestrictedAuthorizedKey("ssh-rsa bad", "/usr/local/bin/opshaven-readonly-force-command", "/etc/opshaven/config.json"), /Ed25519/);
});

test("installer stages only public and runtime material and validates installed tree evidence", async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-install-test-"));
  try {
    await fs.chmod(root, 0o700);
    const raw = setupFixture(root);
    await fs.mkdir(raw.local.runtimeRoot, { recursive: true, mode: 0o700 });
    await writeRuntime(raw.local.runtimeRoot);
    await fs.writeFile(raw.local.wrapperTemplatePath, "#!/bin/sh\nexec /usr/bin/setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all --reset-env /usr/bin/env PATH=/usr/bin:/bin /usr/bin/node /usr/lib/opshaven/read-only-dispatcher.js \"$@\"\n", { mode: 0o600 });
    await fs.writeFile(raw.local.restrictedAuthorizedKeyFile, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA fixture\n", { mode: 0o600 });
    await fs.writeFile(raw.policyConfigPath, "{}\n", { mode: 0o600 });
    await fs.writeFile(`${raw.policyConfigPath}.dispatcher.json`, `${JSON.stringify(remotePolicy(root))}\n`, { mode: 0o600 });
    for (const file of [raw.target.knownHostsFile, raw.target.identityFile, raw.local.capabilityDeclarationPath, raw.local.operatorPrivateKeyFile, raw.local.operatorPublicKeyFile]) await fs.writeFile(file, "fixture\n", { mode: 0o600 });
    const config = parseRemoteSetupConfig(raw);
    const preflight: RemoteSetupPreflightReport = { ok: true, checkedAt: new Date().toISOString(), nodePath: "/usr/bin/node", remote: { platform: "Linux", distribution: "ubuntu", version: "26.04", architecture: "x86_64", nodePath: "/usr/bin/node", nodeVersion: "v22.23.1", freeBytes: 536870912, installation: { accountExists: false, runtimeExists: false, wrapperExists: false, configExists: false, receiptExists: false } }, checks: [] };
    const transport = new RecordingTransport();
    const result = await installRestrictedRuntime(config, preflight, transport);
    assert.equal(result.ok, true);
    assert.equal(result.runtimeTreeSha256, transport.treeHash);
    assert.deepEqual(transport.uploadedNames.sort(), ["authorized_keys", "installer.py", "plan.json", "remote-config.json", "runtime", "runtime-manifest.json", "wrapper"]);
    assert.equal(transport.uploadedNames.some((name) => /private|identity/i.test(name)), false);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
