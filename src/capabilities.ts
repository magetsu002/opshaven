import { createHash, sign, verify } from "node:crypto";
import { canonicalize, sha256 } from "./canonical.js";
import type { LimitsConfig, OpsHavenConfig, ResourceKind } from "./config.js";
import { OpsHavenError } from "./errors.js";
import { READ_ONLY_OPERATIONS, type ReadOnlyOperationName } from "./remote/read-only-policy.js";
import { readRegularFile, readRegularTextFile } from "./safe-fs.js";
import type { OperationName } from "./policy.js";

export type CapabilityMode = "read-only" | "controlled";
export type CapabilityOperation = OperationName | "get_state_fingerprint";

export interface CapabilityPayload {
  version: 1;
  mode: CapabilityMode;
  policyVersion: string;
  allowedOperations: CapabilityOperation[];
  allowedResources: Record<string, string[]>;
  limits: LimitsConfig;
  dispatcherSha256: string;
  issuedAt: string;
  expiresAt: string;
}

export interface SignedCapabilityManifest {
  payload: string;
  signature: string;
}

export interface VerifiedCapability {
  payload: CapabilityPayload;
  hash: string;
}

export const CONTROLLED_OPERATIONS: readonly CapabilityOperation[] = [
  "get_host_summary",
  "get_deployed_commit",
  "get_service_status",
  "get_container_status",
  "get_runtime_config_status",
  "get_reverse_proxy_summary",
  "get_firewall_summary",
  "run_health_probe",
  "get_redacted_logs",
  "get_monitoring_status",
  "get_backup_status",
  "get_restore_readiness",
  "restart_service",
  "deploy_commit",
  "rollback_deployment",
  "get_state_fingerprint",
];

const READ_ONLY_CEILING = new Set<string>(READ_ONLY_OPERATIONS);
const CONTROLLED_CEILING = new Set<string>(CONTROLLED_OPERATIONS);
const ENCODED = /^[A-Za-z0-9_-]{1,262144}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const POLICY_VERSION = /^[A-Za-z0-9._-]{1,64}$/;
const RESOURCE_ID = /^[a-z][a-z0-9._-]{0,63}$/;

const RESOURCE_KINDS: Record<CapabilityOperation, readonly ResourceKind[]> = {
  get_host_summary: ["host"],
  get_deployed_commit: ["deployment"],
  get_service_status: ["service"],
  get_container_status: ["container"],
  get_runtime_config_status: ["application"],
  get_reverse_proxy_summary: ["proxy"],
  get_firewall_summary: ["host"],
  run_health_probe: ["probe"],
  get_redacted_logs: ["service", "container"],
  get_monitoring_status: ["monitoring"],
  get_backup_status: ["backup"],
  get_restore_readiness: ["backup"],
  restart_service: ["service"],
  deploy_commit: ["deployment"],
  rollback_deployment: ["deployment"],
  get_state_fingerprint: ["service", "deployment"],
};

function plain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const expected = new Set(allowed);
  if (Object.keys(value).some((key) => !expected.has(key)) || allowed.some((key) => !(key in value))) {
    throw new OpsHavenError("POLICY_DENIED", `${label} has an incompatible schema.`);
  }
}

function boundedLimits(value: unknown): LimitsConfig {
  if (!plain(value)) throw new OpsHavenError("POLICY_DENIED", "Capability limits are malformed.");
  exactKeys(value, ["timeoutMs", "maxBytes", "maxLines"], "Capability limits");
  const timeoutMs = value.timeoutMs;
  const maxBytes = value.maxBytes;
  const maxLines = value.maxLines;
  if (
    !Number.isInteger(timeoutMs)
    || (timeoutMs as number) < 100
    || (timeoutMs as number) > 120000
    || !Number.isInteger(maxBytes)
    || (maxBytes as number) < 1024
    || (maxBytes as number) > 1048576
    || !Number.isInteger(maxLines)
    || (maxLines as number) < 1
    || (maxLines as number) > 5000
  ) {
    throw new OpsHavenError("POLICY_DENIED", "Capability limits are outside the compiled ceiling.");
  }
  return { timeoutMs: timeoutMs as number, maxBytes: maxBytes as number, maxLines: maxLines as number };
}

function sortedUniqueStrings(value: unknown, label: string, pattern: RegExp, max: number): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > max) {
    throw new OpsHavenError("POLICY_DENIED", `${label} must be a non-empty bounded array.`);
  }
  const result = value.map((item) => {
    if (typeof item !== "string" || !pattern.test(item)) {
      throw new OpsHavenError("POLICY_DENIED", `${label} contains an invalid value.`);
    }
    return item;
  });
  const sorted = [...result].sort();
  if (new Set(sorted).size !== sorted.length || sorted.some((item, index) => item !== result[index])) {
    throw new OpsHavenError("POLICY_DENIED", `${label} must be sorted and unique.`);
  }
  return result;
}

export function parseCapabilityPayload(value: unknown): CapabilityPayload {
  if (!plain(value)) throw new OpsHavenError("POLICY_DENIED", "Capability payload is malformed.");
  exactKeys(
    value,
    [
      "version",
      "mode",
      "policyVersion",
      "allowedOperations",
      "allowedResources",
      "limits",
      "dispatcherSha256",
      "issuedAt",
      "expiresAt",
    ],
    "Capability payload",
  );
  if (value.version !== 1 || (value.mode !== "read-only" && value.mode !== "controlled")) {
    throw new OpsHavenError("POLICY_DENIED", "Capability version or mode is incompatible.");
  }
  if (typeof value.policyVersion !== "string" || !POLICY_VERSION.test(value.policyVersion)) {
    throw new OpsHavenError("POLICY_DENIED", "Capability policy version is invalid.");
  }
  if (typeof value.dispatcherSha256 !== "string" || !SHA256.test(value.dispatcherSha256)) {
    throw new OpsHavenError("POLICY_DENIED", "Capability dispatcher hash is invalid.");
  }
  if (
    typeof value.issuedAt !== "string"
    || typeof value.expiresAt !== "string"
    || !Number.isFinite(Date.parse(value.issuedAt))
    || !Number.isFinite(Date.parse(value.expiresAt))
  ) {
    throw new OpsHavenError("POLICY_DENIED", "Capability timestamps are invalid.");
  }
  const operations = sortedUniqueStrings(value.allowedOperations, "Capability operations", /^[a-z][a-z0-9_]{0,63}$/, 64) as CapabilityOperation[];
  if (!plain(value.allowedResources)) {
    throw new OpsHavenError("POLICY_DENIED", "Capability resources are malformed.");
  }
  const resources: Record<string, string[]> = {};
  if (Object.keys(value.allowedResources).some((operation) => !operations.includes(operation as CapabilityOperation))) {
    throw new OpsHavenError("POLICY_DENIED", "Capability resources contain an undeclared operation.");
  }
  for (const operation of operations) {
    resources[operation] = sortedUniqueStrings(
      value.allowedResources[operation],
      `Capability resources for ${operation}`,
      RESOURCE_ID,
      512,
    );
  }
  return {
    version: 1,
    mode: value.mode,
    policyVersion: value.policyVersion,
    allowedOperations: operations,
    allowedResources: resources,
    limits: boundedLimits(value.limits),
    dispatcherSha256: value.dispatcherSha256,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
  };
}

export function encodeCapabilityPayload(payload: CapabilityPayload): string {
  return Buffer.from(canonicalize(payload), "utf8").toString("base64url");
}

export function signCapabilityManifest(payload: CapabilityPayload, privateKey: Uint8Array): SignedCapabilityManifest {
  const encoded = encodeCapabilityPayload(payload);
  return {
    payload: encoded,
    signature: sign(null, Buffer.from(encoded, "utf8"), privateKey).toString("base64url"),
  };
}

export function parseSignedCapabilityManifest(value: unknown): SignedCapabilityManifest {
  if (!plain(value)) throw new OpsHavenError("POLICY_DENIED", "Signed capability manifest is missing or malformed.");
  exactKeys(value, ["payload", "signature"], "Signed capability manifest");
  if (
    typeof value.payload !== "string"
    || typeof value.signature !== "string"
    || !ENCODED.test(value.payload)
    || !ENCODED.test(value.signature)
  ) {
    throw new OpsHavenError("POLICY_DENIED", "Signed capability manifest is malformed.");
  }
  return { payload: value.payload, signature: value.signature };
}

export function verifyCapabilityManifest(
  config: OpsHavenConfig,
  signedManifest: SignedCapabilityManifest,
  publicKey: Uint8Array,
  expectedMode: CapabilityMode,
  actualDispatcherSha256: string,
  now = Date.now(),
): VerifiedCapability {
  const valid = verify(
    null,
    Buffer.from(signedManifest.payload, "utf8"),
    publicKey,
    Buffer.from(signedManifest.signature, "base64url"),
  );
  if (!valid) throw new OpsHavenError("POLICY_DENIED", "Capability signature is invalid.");
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(signedManifest.payload, "base64url").toString("utf8")) as unknown;
  } catch {
    throw new OpsHavenError("POLICY_DENIED", "Capability payload is malformed.");
  }
  const payload = parseCapabilityPayload(decoded);
  const ceiling = expectedMode === "read-only" ? READ_ONLY_CEILING : CONTROLLED_CEILING;
  if (payload.mode !== expectedMode) throw new OpsHavenError("POLICY_DENIED", "Capability mode does not match this dispatcher.");
  if (payload.policyVersion !== config.policyVersion) throw new OpsHavenError("POLICY_DENIED", "Capability policy version is inactive.");
  if (
    payload.limits.timeoutMs !== config.limits.timeoutMs
    || payload.limits.maxBytes !== config.limits.maxBytes
    || payload.limits.maxLines !== config.limits.maxLines
  ) {
    throw new OpsHavenError("POLICY_DENIED", "Capability limits do not match trusted policy.");
  }
  if (payload.dispatcherSha256 !== actualDispatcherSha256) {
    throw new OpsHavenError("POLICY_DENIED", "Dispatcher artifact does not match the operator capability.");
  }
  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  if (issuedAt > now + 300000 || expiresAt <= now || expiresAt <= issuedAt || expiresAt - issuedAt > 31536000000) {
    throw new OpsHavenError("POLICY_DENIED", "Capability is stale, expired, or has an invalid lifetime.");
  }
  for (const operation of payload.allowedOperations) {
    if (!ceiling.has(operation)) {
      throw new OpsHavenError("POLICY_DENIED", "Capability attempts to exceed the compiled dispatcher authority.");
    }
    const kinds = RESOURCE_KINDS[operation];
    if (!kinds) throw new OpsHavenError("POLICY_DENIED", "Capability operation is unsupported.");
    for (const id of payload.allowedResources[operation] ?? []) {
      const resource = config.resources.get(id);
      if (!resource || !kinds.includes(resource.kind)) {
        throw new OpsHavenError("POLICY_DENIED", "Capability references an unavailable or incompatible logical resource.");
      }
      if (expectedMode === "read-only" && resource.kind === "container") {
        throw new OpsHavenError("POLICY_DENIED", "Read-only capability cannot grant Docker socket authority.");
      }
    }
  }
  return { payload, hash: sha256(payload) };
}

export function assertCapabilityAllows(
  capability: VerifiedCapability,
  operation: string,
  resourceId: string,
  limits: LimitsConfig,
): void {
  if (!capability.payload.allowedOperations.includes(operation as CapabilityOperation)) {
    throw new OpsHavenError("POLICY_DENIED", "Operation is not present in the active operator capability.");
  }
  if (!(capability.payload.allowedResources[operation] ?? []).includes(resourceId)) {
    throw new OpsHavenError("POLICY_DENIED", "Resource is not present in the active operator capability.");
  }
  if (
    limits.timeoutMs !== capability.payload.limits.timeoutMs
    || limits.maxBytes !== capability.payload.limits.maxBytes
    || limits.maxLines !== capability.payload.limits.maxLines
  ) {
    throw new OpsHavenError("POLICY_DENIED", "Request limits do not match the active operator capability.");
  }
}

export async function dispatcherArtifactSha256(filePath: string): Promise<string> {
  const artifact = await readRegularFile(filePath, "Dispatcher artifact", { maxBytes: 16777216, code: "POLICY_DENIED" });
  return createHash("sha256").update(artifact).digest("hex");
}

export function capabilityManifestPath(configPath: string): string {
  return `${configPath}.capability.json`;
}

export async function loadVerifiedCapability(
  config: OpsHavenConfig,
  configPath: string,
  expectedMode: CapabilityMode,
  dispatcherPath: string,
): Promise<VerifiedCapability> {
  const manifestText = await readRegularTextFile(capabilityManifestPath(configPath), "Capability manifest", {
    maxBytes: 1048576,
    code: "POLICY_DENIED",
  });
  let manifest: unknown;
  try {
    manifest = JSON.parse(manifestText) as unknown;
  } catch {
    throw new OpsHavenError("POLICY_DENIED", "Capability manifest is not valid JSON.");
  }
  const publicKey = await readRegularFile(config.approvals.verificationPublicKeyFile, "Operator capability public key", {
    maxBytes: 65536,
    code: "POLICY_DENIED",
  });
  return verifyCapabilityManifest(
    config,
    parseSignedCapabilityManifest(manifest),
    publicKey,
    expectedMode,
    await dispatcherArtifactSha256(dispatcherPath),
  );
}

export function buildCapabilityPayload(
  config: OpsHavenConfig,
  mode: CapabilityMode,
  dispatcherSha256: string,
  expiresAt: string,
  issuedAt = new Date().toISOString(),
): CapabilityPayload {
  const candidates = [...(mode === "read-only" ? READ_ONLY_OPERATIONS : CONTROLLED_OPERATIONS)].sort() as CapabilityOperation[];
  const operations: CapabilityOperation[] = [];
  const resources: Record<string, string[]> = {};
  for (const operation of candidates) {
    const kinds = RESOURCE_KINDS[operation];
    const compatible = [...config.resources.values()]
      .filter((resource) => kinds.includes(resource.kind) && !(mode === "read-only" && resource.kind === "container"))
      .map((resource) => resource.id)
      .sort();
    if (compatible.length === 0) continue;
    operations.push(operation);
    resources[operation] = compatible;
  }
  return {
    version: 1,
    mode,
    policyVersion: config.policyVersion,
    allowedOperations: operations,
    allowedResources: resources,
    limits: { ...config.limits },
    dispatcherSha256,
    issuedAt,
    expiresAt,
  };
}
