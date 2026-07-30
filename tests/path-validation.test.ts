import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";

const raw = {
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
  ],
};

test("absolute path validation rejects oversized adversarial input", () => {
  const oversized = `/${"-".repeat(5000)}`;
  assert.throws(
    () => parseConfig({ ...raw, audit: { path: oversized } }),
    (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID",
  );
});
