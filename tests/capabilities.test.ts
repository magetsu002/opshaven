import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  buildCapabilityPayload,
  parseSignedCapabilityManifest,
  signCapabilityManifest,
  verifyCapabilityManifest,
  type CapabilityPayload,
} from "../src/capabilities.js";
import { parseConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";

const config = parseConfig({
  version: 1,
  policyVersion: "v1",
  limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
  audit: { path: "/var/lib/opshaven/audit.jsonl" },
  approvals: {
    directory: "/var/lib/opshaven/approvals",
    secretFile: "/var/lib/opshaven/approval.key",
    signingPrivateKeyFile: "/var/lib/opshaven/private.pem",
    verificationPublicKeyFile: "/etc/opshaven/public.pem",
    remoteUsedDirectory: "/var/lib/opshaven/remote-used",
    defaultTtlSeconds: 300,
  },
  secretFingerprints: [],
  resources: [
    {
      id: "host.main",
      kind: "host",
      address: "host.internal",
      port: 22,
      user: "opshaven",
      knownHostsFile: "/etc/opshaven/known_hosts",
      identityFile: "/etc/opshaven/id_ed25519",
      connectTimeoutMs: 5000,
    },
    { id: "svc.web", kind: "service", hostId: "host.main", unit: "web.service" },
  ],
});

const keys = generateKeyPairSync("ed25519");
const privateKey = keys.privateKey.export({ type: "pkcs8", format: "pem" }) as Uint8Array;
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }) as Uint8Array;
const now = Date.parse("2026-07-30T20:00:00.000Z");

function payload(overrides: Partial<CapabilityPayload> = {}): CapabilityPayload {
  return {
    version: 1,
    mode: "controlled",
    policyVersion: "v1",
    allowedOperations: ["get_service_status"],
    allowedResources: { get_service_status: ["svc.web"] },
    limits: { ...config.limits },
    dispatcherSha256: "a".repeat(64),
    issuedAt: "2026-07-30T19:55:00.000Z",
    expiresAt: "2026-07-30T20:30:00.000Z",
    ...overrides,
  };
}

function denied(action: () => unknown): boolean {
  try {
    action();
    return false;
  } catch (error) {
    return error instanceof OpsHavenError && error.code === "POLICY_DENIED";
  }
}

test("operator capability verifies exact policy, resources, limits, and artifact", () => {
  const verified = verifyCapabilityManifest(
    config,
    signCapabilityManifest(payload(), privateKey),
    publicKey,
    "controlled",
    "a".repeat(64),
    now,
  );
  assert.equal(verified.payload.allowedResources.get_service_status?.[0], "svc.web");
  assert.match(verified.hash, /^[a-f0-9]{64}$/);
});

test("capability generation omits operations without compatible configured resources", () => {
  const generated = buildCapabilityPayload(
    config,
    "read-only",
    "a".repeat(64),
    "2026-07-30T20:30:00.000Z",
    "2026-07-30T19:55:00.000Z",
  );
  assert.deepEqual(generated.allowedResources.get_host_summary, ["host.main"]);
  assert.deepEqual(generated.allowedResources.get_service_status, ["svc.web"]);
  assert.equal(generated.allowedOperations.includes("get_backup_status"), false);
  assert.equal(generated.allowedResources.get_backup_status, undefined);
  assert.equal(generated.allowedOperations.includes("get_deployed_commit"), false);
  assert.equal(generated.allowedResources.get_deployed_commit, undefined);
});

test("capability rejects unsigned, altered, and expired manifests", () => {
  assert.equal(denied(() => parseSignedCapabilityManifest({ payload: "unsigned" })), true);
  const signed = signCapabilityManifest(payload(), privateKey);
  const altered = { ...signed, payload: `${signed.payload}a` };
  assert.equal(denied(() => verifyCapabilityManifest(config, altered, publicKey, "controlled", "a".repeat(64), now)), true);
  const expired = signCapabilityManifest(payload({ expiresAt: "2026-07-30T19:59:59.000Z" }), privateKey);
  assert.equal(denied(() => verifyCapabilityManifest(config, expired, publicKey, "controlled", "a".repeat(64), now)), true);
});

test("capability rejects incompatible mode, artifact, and resource expansion", () => {
  const signed = signCapabilityManifest(payload(), privateKey);
  assert.equal(denied(() => verifyCapabilityManifest(config, signed, publicKey, "read-only", "a".repeat(64), now)), true);
  assert.equal(denied(() => verifyCapabilityManifest(config, signed, publicKey, "controlled", "b".repeat(64), now)), true);
  const unknownResource = signCapabilityManifest(payload({ allowedResources: { get_service_status: ["svc.unknown"] } }), privateKey);
  assert.equal(denied(() => verifyCapabilityManifest(config, unknownResource, publicKey, "controlled", "a".repeat(64), now)), true);
});

test("capability rejects authority outside the compiled dispatcher ceiling", () => {
  const expanded = payload({
    allowedOperations: ["arbitrary_shell" as CapabilityPayload["allowedOperations"][number]],
    allowedResources: { arbitrary_shell: ["host.main"] },
  });
  const signed = signCapabilityManifest(expanded, privateKey);
  assert.equal(denied(() => verifyCapabilityManifest(config, signed, publicKey, "controlled", "a".repeat(64), now)), true);
});
