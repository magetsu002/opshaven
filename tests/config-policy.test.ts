import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";
import { PolicyEngine } from "../src/policy.js";

const raw = {
  version: 1,
  policyVersion: "v1",
  limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
  audit: { path: "/var/lib/opshaven/audit.jsonl" },
  approvals: { directory: "/var/lib/opshaven/approvals", secretFile: "/var/lib/opshaven/approval.key", signingPrivateKeyFile: "/var/lib/opshaven/approval-private.pem", verificationPublicKeyFile: "/etc/opshaven/approval-public.pem", remoteUsedDirectory: "/var/lib/opshaven/remote-used", defaultTtlSeconds: 300 },
  secretFingerprints: [],
  resources: [
    { id: "host.main", kind: "host", address: "example.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id_ed25519", connectTimeoutMs: 5000 },
    { id: "svc.web", kind: "service", hostId: "host.main", unit: "example.service" },
    { id: "dep.web", kind: "deployment", hostId: "host.main", repositoryPath: "/srv/example/repository", releasesPath: "/srv/example/releases", currentSymlink: "/srv/example/current", allowedRefs: ["refs/remotes/origin/main"], activation: "systemd", serviceIds: ["svc.web"], probeIds: [], buildSteps: [], checkSteps: [], fetchBeforeDeploy: false, migrationPolicy: "none" },
  ],
};

test("configuration rejects unknown fields", () => {
  assert.throws(() => parseConfig({ ...raw, surprise: true }), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
});

test("configuration rejects cross-host or wrong-kind resource references", () => {
  const otherHost = { id: "host.other", kind: "host", address: "other.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/other_known_hosts", identityFile: "/etc/opshaven/other_id", connectTimeoutMs: 5000 };
  const otherService = { id: "svc.other", kind: "service", hostId: "host.other", unit: "other.service" };
  const deployment = { ...raw.resources[2], serviceIds: ["svc.other"] };
  assert.throws(() => parseConfig({ ...raw, resources: [raw.resources[0], raw.resources[1], deployment, otherHost, otherService] }), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
  const wrongKind = { ...raw.resources[2], serviceIds: ["host.main"] };
  assert.throws(() => parseConfig({ ...raw, resources: [raw.resources[0], raw.resources[1], wrongKind] }), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
});

test("configuration rejects option-like names, refs, and secret-bearing probe URLs", () => {
  const unsafeService = { ...raw.resources[1], unit: "--help" };
  assert.throws(() => parseConfig({ ...raw, resources: [raw.resources[0], unsafeService] }), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
  const unsafeDeployment = { ...raw.resources[2], allowedRefs: ["--all"] };
  assert.throws(() => parseConfig({ ...raw, resources: [raw.resources[0], raw.resources[1], unsafeDeployment] }), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
  const unsafeProbe = { id: "probe.web", kind: "probe", hostId: "host.main", url: "https://example.internal/health?token=secret", method: "GET", expectedStatus: [200], timeoutMs: 1000 };
  assert.throws(() => parseConfig({ ...raw, resources: [raw.resources[0], unsafeProbe] }), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
});

test("policy resolves only logical IDs", () => {
  const policy = new PolicyEngine(parseConfig(raw));
  const resolved = policy.resolve("get_service_status", { resourceId: "svc.web" });
  assert.equal(resolved.hostId, "host.main");
  assert.equal(resolved.args.resourceId, "svc.web");
  assert.throws(() => policy.resolve("get_service_status", { resourceId: "example.service" }), (error: unknown) => error instanceof OpsHavenError && error.code === "UNKNOWN_RESOURCE");
});

test("mutation input rejects extra flags and malformed commits", () => {
  const policy = new PolicyEngine(parseConfig(raw));
  assert.throws(() => policy.resolve("restart_service", { resourceId: "svc.web", flags: "--now" }), (error: unknown) => error instanceof OpsHavenError && error.code === "INVALID_ARGUMENTS");
  assert.throws(() => policy.resolve("deploy_commit", { resourceId: "dep.web", commit: "main", dryRun: true }), (error: unknown) => error instanceof OpsHavenError && error.code === "INVALID_ARGUMENTS");
});
