import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  buildDeclarationBinding,
  capabilityDeclarationHash,
  compareCapabilityDeclarations,
  parseCapabilityDeclaration,
  signDeclarationBinding,
  verifyDeclarationBinding,
} from "../src/capability-declaration.js";
import { parseConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";

const declaration = parseCapabilityDeclaration({
  version: 1,
  build: "fixture-1",
  modes: {
    controlled: {
      operations: ["get_host_summary"],
      remoteHandlers: ["inspection"],
      filesystemRead: ["root-owned trust files"],
      filesystemWrite: ["request replay state"],
      executables: ["uname"],
      networkAccess: ["restricted SSH stdio"],
      sudoRequirements: [],
      outputFields: ["structured status summaries"],
    },
    "read-only": {
      operations: ["get_host_summary"],
      remoteHandlers: ["inspection"],
      filesystemRead: ["root-owned trust files"],
      filesystemWrite: ["request replay state"],
      executables: ["uname"],
      networkAccess: ["restricted SSH stdio"],
      sudoRequirements: [],
      outputFields: ["structured status summaries"],
    },
  },
});

const config = parseConfig({
  version: 1,
  policyVersion: "v1",
  limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
  audit: { path: "/var/lib/opshaven/audit.jsonl" },
  approvals: {
    directory: "/var/lib/opshaven/approvals",
    secretFile: "/var/lib/opshaven/secret",
    signingPrivateKeyFile: "/var/lib/opshaven/private.pem",
    verificationPublicKeyFile: "/etc/opshaven/public.pem",
    remoteUsedDirectory: "/var/lib/opshaven/remote-used",
    defaultTtlSeconds: 300,
  },
  secretFingerprints: [],
  resources: [{ id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id", connectTimeoutMs: 5000 }],
});

const keys = generateKeyPairSync("ed25519");
const privateKey = keys.privateKey.export({ type: "pkcs8", format: "pem" }) as Uint8Array;
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }) as Uint8Array;
const now = Date.parse("2026-07-30T20:00:00.000Z");

test("capability comparison detects every declared authority expansion", () => {
  const expanded = structuredClone(declaration);
  expanded.modes.controlled.executables = ["sh", "uname"];
  const comparison = compareCapabilityDeclarations(declaration, expanded);
  assert.equal(comparison.authorityExpanded, true);
  assert.deepEqual(comparison.modes.controlled[0], { field: "executables", added: ["sh"], removed: [] });
});

test("operator declaration binding authenticates artifact and declaration hashes", () => {
  const payload = buildDeclarationBinding(
    config,
    "controlled",
    "a".repeat(64),
    capabilityDeclarationHash(declaration),
    "2026-07-30T21:00:00.000Z",
    "2026-07-30T19:00:00.000Z",
  );
  const signed = signDeclarationBinding(payload, privateKey);
  const verified = verifyDeclarationBinding(config, signed, publicKey, "controlled", "a".repeat(64), capabilityDeclarationHash(declaration), now);
  assert.equal(verified.payload.mode, "controlled");
});

test("declaration binding rejects artifact, declaration, expiry, and signature changes", () => {
  const payload = buildDeclarationBinding(config, "controlled", "a".repeat(64), capabilityDeclarationHash(declaration), "2026-07-30T21:00:00.000Z", "2026-07-30T19:00:00.000Z");
  const signed = signDeclarationBinding(payload, privateKey);
  const denied = (action: () => unknown) => assert.throws(action, (error: unknown) => error instanceof OpsHavenError && error.code === "POLICY_DENIED");
  denied(() => verifyDeclarationBinding(config, signed, publicKey, "controlled", "b".repeat(64), capabilityDeclarationHash(declaration), now));
  denied(() => verifyDeclarationBinding(config, signed, publicKey, "controlled", "a".repeat(64), "b".repeat(64), now));
  denied(() => verifyDeclarationBinding(config, signed, publicKey, "controlled", "a".repeat(64), capabilityDeclarationHash(declaration), Date.parse("2026-07-30T21:00:01.000Z")));
  denied(() => verifyDeclarationBinding(config, { ...signed, signature: `${signed.signature.slice(0, -1)}A` }, publicKey, "controlled", "a".repeat(64), capabilityDeclarationHash(declaration), now));
});
