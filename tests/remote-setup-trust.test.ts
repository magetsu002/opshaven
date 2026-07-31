import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import type { RemoteInstallResult } from "../src/setup/install.js";
import { parseRemoteSetupConfig } from "../src/setup/remote.js";
import { provisionRemoteTrust } from "../src/setup/trust.js";
import type { RemoteAdminTransport, SetupCommandResult } from "../src/setup/transport.js";

function hash(value: Uint8Array | string): string { return createHash("sha256").update(value).digest("hex"); }

function policy(root: string, publicKey: string): unknown {
  return {
    version: 1,
    policyVersion: "setup-trust-v1",
    limits: { timeoutMs: 15000, maxBytes: 131072, maxLines: 1000 },
    audit: { path: "/var/lib/opshaven/audit.jsonl" },
    approvals: { directory: "/var/lib/opshaven/unused", secretFile: "/var/lib/opshaven/unused-secret", signingPrivateKeyFile: "/var/lib/opshaven/unused-private", verificationPublicKeyFile: publicKey, remoteUsedDirectory: "/var/lib/opshaven/remote-used", defaultTtlSeconds: 300 },
    secretFingerprints: [],
    resources: [
      { id: "host.main", kind: "host", address: "localhost", port: 22, user: "opshaven", knownHostsFile: `${root}/known_hosts`, identityFile: `${root}/identity`, connectTimeoutMs: 5000 },
      { id: "app.main", kind: "application", hostId: "host.main", runtimeConfigKeys: ["NODE_ENV"] },
      { id: "svc.main", kind: "service", hostId: "host.main", unit: "opshaven.service" },
      { id: "probe.main", kind: "probe", hostId: "host.main", url: "http://127.0.0.1:8080/health", method: "GET", expectedStatus: [200], timeoutMs: 3000 },
      { id: "dep.main", kind: "deployment", hostId: "host.main", repositoryPath: "/srv/opshaven/repository", releasesPath: "/srv/opshaven/releases", currentSymlink: "/srv/opshaven/current", allowedRefs: ["refs/heads/main"], activation: "systemd", serviceIds: ["svc.main"], probeIds: ["probe.main"], buildSteps: [], checkSteps: [], fetchBeforeDeploy: false, migrationPolicy: "none" },
      { id: "proxy.main", kind: "proxy", hostId: "host.main", provider: "nginx", serviceId: "svc.main", publicNames: ["example.test"] },
      { id: "monitor.main", kind: "monitoring", hostId: "host.main", serviceIds: ["svc.main"], probeIds: ["probe.main"] },
      { id: "backup.main", kind: "backup", hostId: "host.main", statusFile: "/var/lib/opshaven/backup.json", maximumAgeHours: 24 },
    ],
  };
}

class TrustTransport implements RemoteAdminTransport {
  readonly response = generateKeyPairSync("ed25519");
  hashes: Record<string, string> = {};
  uploadedNames: string[] = [];

  async run(): Promise<SetupCommandResult> { return { code: 0, stdout: "", stderr: "" }; }
  async runPrivileged(): Promise<SetupCommandResult> { return { code: 0, stdout: "", stderr: "" }; }

  async upload(localPath: string): Promise<SetupCommandResult> {
    this.uploadedNames = (await fs.readdir(localPath)).sort();
    this.hashes = {
      publicKey: hash(await fs.readFile(path.join(localPath, "operator-public.pem"))),
      capability: hash(await fs.readFile(path.join(localPath, "capability.json"))),
      declaration: hash(await fs.readFile(path.join(localPath, "declaration.json"))),
      binding: hash(await fs.readFile(path.join(localPath, "binding.json"))),
      responsePublic: hash(Buffer.from(String(this.response.publicKey.export({ type: "spki", format: "pem" })))),
    };
    return { code: 0, stdout: "", stderr: "" };
  }

  async runPython(): Promise<SetupCommandResult> {
    return { code: 0, stdout: JSON.stringify({ ok: true, hashes: this.hashes, responsePublic: "/etc/opshaven/config.json.response-public.pem" }), stderr: "" };
  }

  async download(_remotePath: string, localPath: string): Promise<SetupCommandResult> {
    await fs.writeFile(localPath, String(this.response.publicKey.export({ type: "spki", format: "pem" })), { mode: 0o644 });
    return { code: 0, stdout: "", stderr: "" };
  }
}

test("trust provisioning signs read-only authority locally and uploads no private operator material", async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-trust-test-"));
  try {
    const operator = generateKeyPairSync("ed25519");
    const privatePath = path.join(root, "operator-private.pem");
    const publicPath = path.join(root, "operator-public.pem");
    const policyPath = path.join(root, "config.json");
    const dispatcherPath = path.join(root, "read-only-dispatcher.js");
    const declarationPath = path.join(root, "declaration.json");
    await fs.writeFile(privatePath, String(operator.privateKey.export({ type: "pkcs8", format: "pem" })), { mode: 0o600 });
    await fs.writeFile(publicPath, String(operator.publicKey.export({ type: "spki", format: "pem" })), { mode: 0o644 });
    await fs.writeFile(dispatcherPath, "export const dispatcher = true;\n", { mode: 0o755 });
    await fs.copyFile(path.join(process.cwd(), "security", "capability-declaration.json"), declarationPath);
    const rawPolicy = policy(root, "/etc/opshaven/approval-public.pem");
    await fs.writeFile(`${policyPath}.dispatcher.json`, `${JSON.stringify(rawPolicy)}\n`, { mode: 0o600 });
    await fs.writeFile(policyPath, `${JSON.stringify(policy(root, publicPath))}\n`, { mode: 0o600 });
    const setup = parseRemoteSetupConfig({
      version: 1,
      policyConfigPath: policyPath,
      expectedSourceSha: "0123456789abcdef0123456789abcdef01234567",
      target: { host: "vps.example.test", port: 22, adminUser: "ubuntu", knownHostsFile: path.join(root, "known_hosts"), identityFile: path.join(root, "identity"), expectedHostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", privilege: "sudo-noninteractive" },
      local: { runtimeRoot: path.join(root, "runtime"), dispatcherPath, wrapperTemplatePath: path.join(root, "wrapper"), capabilityDeclarationPath: declarationPath, operatorPrivateKeyFile: privatePath, operatorPublicKeyFile: publicPath, restrictedAuthorizedKeyFile: path.join(root, "restricted.pub") },
      remote: { account: "opshaven", runtimeRoot: "/usr/lib/opshaven", configPath: "/etc/opshaven/config.json", wrapperPath: "/usr/local/bin/opshaven-readonly-force-command", stateDirectory: "/var/lib/opshaven", receiptPath: "/var/lib/opshaven/setup-receipt.json", nodeCandidates: ["/usr/bin/node"] },
      trust: { expiresInSeconds: 3600 },
    });
    const transport = new TrustTransport();
    const install: RemoteInstallResult = { ok: true, changed: [], runtimeTreeSha256: "a".repeat(64), backupRoot: "/var/lib/opshaven/backups/test", receiptId: "test" };
    const receipt = await provisionRemoteTrust(setup, install, transport);
    assert.equal(receipt.ok, true);
    assert.match(receipt.dispatcherSha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(transport.uploadedNames, ["binding.json", "capability.json", "declaration.json", "operator-public.pem"]);
    assert.equal(transport.uploadedNames.some((item) => /private|identity/i.test(item)), false);
    const capability = JSON.parse(await fs.readFile(`${policyPath}.capability.json`, "utf8")) as { payload: string };
    const payload = JSON.parse(Buffer.from(capability.payload, "base64url").toString("utf8")) as { mode: string; dispatcherSha256: string };
    assert.equal(payload.mode, "read-only");
    assert.equal(payload.dispatcherSha256, receipt.dispatcherSha256);
    assert.equal(await fs.readFile(`${policyPath}.response-public.pem`, "utf8").then((value) => value.includes("PRIVATE KEY")), false);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("trust provisioning rejects a mismatched operator key pair before upload", async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-trust-mismatch-"));
  try {
    const first = generateKeyPairSync("ed25519");
    const second = generateKeyPairSync("ed25519");
    const privatePath = path.join(root, "private.pem");
    const publicPath = path.join(root, "public.pem");
    const policyPath = path.join(root, "config.json");
    const dispatcherPath = path.join(root, "dispatcher.js");
    const declarationPath = path.join(root, "declaration.json");
    await fs.writeFile(privatePath, String(first.privateKey.export({ type: "pkcs8", format: "pem" })), { mode: 0o600 });
    await fs.writeFile(publicPath, String(second.publicKey.export({ type: "spki", format: "pem" })), { mode: 0o644 });
    await fs.writeFile(dispatcherPath, "fixture\n", { mode: 0o755 });
    await fs.copyFile(path.join(process.cwd(), "security", "capability-declaration.json"), declarationPath);
    await fs.writeFile(`${policyPath}.dispatcher.json`, `${JSON.stringify(policy(root, "/etc/opshaven/approval-public.pem"))}\n`, { mode: 0o600 });
    const setup = parseRemoteSetupConfig({ version: 1, policyConfigPath: policyPath, expectedSourceSha: "0123456789abcdef0123456789abcdef01234567", target: { host: "vps.example.test", port: 22, adminUser: "ubuntu", knownHostsFile: path.join(root, "known_hosts"), identityFile: path.join(root, "identity"), expectedHostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", privilege: "root" }, local: { runtimeRoot: path.join(root, "runtime"), dispatcherPath, wrapperTemplatePath: path.join(root, "wrapper"), capabilityDeclarationPath: declarationPath, operatorPrivateKeyFile: privatePath, operatorPublicKeyFile: publicPath, restrictedAuthorizedKeyFile: path.join(root, "restricted.pub") }, remote: { account: "opshaven", runtimeRoot: "/usr/lib/opshaven", configPath: "/etc/opshaven/config.json", wrapperPath: "/usr/local/bin/opshaven-readonly-force-command", stateDirectory: "/var/lib/opshaven", receiptPath: "/var/lib/opshaven/setup-receipt.json", nodeCandidates: ["/usr/bin/node"] }, trust: { expiresInSeconds: 3600 } });
    const transport = new TrustTransport();
    await assert.rejects(provisionRemoteTrust(setup, { ok: true, changed: [], runtimeTreeSha256: "a".repeat(64), backupRoot: "/var/lib/opshaven/backups/test", receiptId: "test" }, transport), /do not correspond/);
    assert.deepEqual(transport.uploadedNames, []);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
