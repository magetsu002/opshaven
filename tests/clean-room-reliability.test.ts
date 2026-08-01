import assert from "node:assert/strict";
import { constants as fsConstants, promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { OpsHavenError } from "../src/errors.js";
import { formatOperatorError } from "../src/operator-error-boundary.js";
import { inspectRemoteSetupRepair } from "../src/setup/reliability-repair.js";
import type { RemoteSetupConfig } from "../src/setup/remote.js";
import type { RemoteAdminTransport, SetupCommandResult } from "../src/setup/transport.js";

function response(value: unknown): SetupCommandResult {
  return { code: 0, stdout: typeof value === "string" ? value : JSON.stringify(value), stderr: "" };
}

async function fixture(): Promise<{ root: string; config: RemoteSetupConfig }> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-clean-room-regression-"));
  const config: RemoteSetupConfig = {
    version: 1,
    policyConfigPath: path.join(root, "config.json"),
    expectedSourceSha: "1".repeat(40),
    target: {
      host: "fixture.invalid",
      port: 22,
      adminUser: "root",
      knownHostsFile: path.join(root, "known_hosts"),
      identityFile: path.join(root, "identity"),
      expectedHostKeySha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      privilege: "root",
    },
    local: {
      runtimeRoot: path.join(root, "dist"),
      dispatcherPath: path.join(root, "dist/src/remote/dispatcher.js"),
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
    trust: { expiresInSeconds: 3600 },
  };
  await fs.writeFile(config.policyConfigPath, JSON.stringify({
    version: 1,
    policyVersion: "fixture",
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    audit: { path: path.join(root, "audit.jsonl") },
    approvals: {
      directory: path.join(root, "approvals"),
      secretFile: path.join(root, "approval-secret"),
      signingPrivateKeyFile: path.join(root, "approval-private.pem"),
      verificationPublicKeyFile: path.join(root, "approval-public.pem"),
      remoteUsedDirectory: path.join(root, "remote-used"),
      defaultTtlSeconds: 300,
    },
    secretFingerprints: [],
    resources: [],
  }), { mode: 0o600 });
  return { root, config };
}

class PartialBaselineTransport implements RemoteAdminTransport {
  async run(): Promise<SetupCommandResult> { throw new Error("unexpected run"); }
  async runPrivileged(): Promise<SetupCommandResult> { throw new Error("unexpected privileged run"); }
  async upload(): Promise<SetupCommandResult> { throw new Error("unexpected upload"); }
  async download(): Promise<SetupCommandResult> { throw new Error("unexpected download"); }
  async runPython(script: string): Promise<SetupCommandResult> {
    if (script.includes("receiptPresent") && script.includes("canonical-pair")) {
      return response({
        version: 1,
        kind: "partial",
        present: ["/var/lib/opshaven/remote-state.json"],
        missing: ["/var/lib/opshaven/setup-receipt.json"],
        receiptPresent: false,
        statePresent: true,
        transactionPresent: false,
        detail: "canonical generation identity is partial",
      });
    }
    if (script.includes("integrityValid") && script.includes("lastCompletedPhase")) {
      return response({ status: "absent" });
    }
    return response({
      status: "inconsistent",
      source: "installed remote state",
      schemaVersion: 2,
      generation: null,
      recordedIdentityMatches: false,
      sourceSha: null,
      dispatcherMode: null,
      runtimeSha256: null,
      dispatcherSha256: null,
      policyVersion: null,
      policySha256: null,
      capabilityIdentitySha256: null,
      capabilityArtifactSha256: null,
      declarationSha256: null,
      operatorVerificationIdentity: null,
      applicationScope: [],
      applicationScopeSha256: null,
      platform: "Linux",
      architecture: "x86_64",
      nodeVersion: "v22.18.0",
      detail: "installed generation evidence is partial: setup receipt is missing while managed artifacts remain",
    });
  }
}

test("repair inspects a partial installed baseline even without a transaction marker", async () => {
  const value = await fixture();
  try {
    const plan = await inspectRemoteSetupRepair(value.config, new PartialBaselineTransport());
    assert.notEqual(plan.action, "none");
    assert.equal(plan.action, "clean-reinstall-required");
    assert.match(plan.changes.join("; "), /partial|incomplete|evidence|canonical receipts/i);
  } finally {
    await fs.rm(value.root, { recursive: true, force: true });
  }
});

test("normal operator errors never expose an embedded Python traceback", () => {
  const formatted = formatOperatorError(new OpsHavenError(
    "SSH_FAILED",
    "Remote transaction preparation failed safely: Traceback (most recent call last): /tmp/opshaven.py RuntimeError: previous generation identity is partial.",
    true,
  ), ["setup", "remote"]);
  assert.doesNotMatch(formatted, /Traceback|RuntimeError|\/tmp\//);
  assert.match(formatted, /repair|incomplete identity evidence|health check/i);
});

test("clean build output keeps installed CLI entry points executable", async () => {
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  for (const relative of ["dist/src/cli-entry.js", "dist/src/mcp-entry.js"]) {
    const target = path.join(repositoryRoot, relative);
    const handle = await fs.open(target, fsConstants.O_RDONLY | noFollow);
    try {
      const stat = await handle.stat();
      assert.ok(stat.isFile());
      assert.ok((stat.mode & 0o111) !== 0, `${relative} must retain an executable bit after a clean build`);
      const source = await handle.readFile("utf8");
      assert.match(source, /^#!\/usr\/bin\/env node\n/);
    } finally {
      await handle.close();
    }
  }
});
