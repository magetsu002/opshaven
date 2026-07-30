import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { assertRemoteConfinement } from "../src/remote/confinement.js";
import { parseConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";

async function fixture() {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-confinement-"));
  const uid = process.getuid?.() ?? 0;
  const configPath = path.join(root, "config.json");
  const publicKey = path.join(root, "public.pem");
  const responseKey = `${configPath}.response-private.pem`;
  const manifest = `${configPath}.capability.json`;
  const artifact = path.join(root, "dispatcher.js");
  const state = path.join(root, "state");
  await fs.mkdir(state, { mode: 0o700 });
  for (const [file, mode] of [[configPath, 0o600], [publicKey, 0o600], [responseKey, 0o600], [manifest, 0o600], [artifact, 0o700]] as const) {
    await fs.writeFile(file, "fixture\n", { mode });
  }
  const config = parseConfig({
    version: 1,
    policyVersion: "v1",
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    audit: { path: path.join(root, "audit.jsonl") },
    approvals: {
      directory: path.join(root, "approvals"),
      secretFile: path.join(root, "secret"),
      signingPrivateKeyFile: path.join(root, "private.pem"),
      verificationPublicKeyFile: publicKey,
      remoteUsedDirectory: state,
      defaultTtlSeconds: 300,
    },
    secretFingerprints: [],
    resources: [{ id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: path.join(root, "known_hosts"), identityFile: path.join(root, "id"), connectTimeoutMs: 5000 }],
  });
  return { root, uid, config, configPath, artifact, manifest };
}

test("remote confinement accepts protected real files and creates private temp state", async () => {
  const value = await fixture();
  const result = await assertRemoteConfinement(value.config, value.configPath, value.artifact, "controlled", value.uid, value.uid);
  assert.equal((await fs.stat(result.privateTmp)).mode & 0o777, 0o700);
});

test("remote confinement rejects symlink and writable policy substitution", async () => {
  const value = await fixture();
  const real = `${value.manifest}.real`;
  await fs.rename(value.manifest, real);
  await fs.symlink(real, value.manifest);
  await assert.rejects(
    assertRemoteConfinement(value.config, value.configPath, value.artifact, "controlled", value.uid, value.uid),
    (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED",
  );
  await fs.rm(value.manifest);
  await fs.rename(real, value.manifest);
  await fs.chmod(value.configPath, 0o666);
  await assert.rejects(assertRemoteConfinement(value.config, value.configPath, value.artifact, "controlled", value.uid, value.uid));
});
