import { createHash, sign, verify } from "node:crypto";
import { canonicalize, sha256 } from "./canonical.js";
import type { OpsHavenConfig } from "./config.js";
import { OpsHavenError } from "./errors.js";
import { readRegularFile, readRegularTextFile } from "./safe-fs.js";

export const CAPABILITY_FIELDS = [
  "operations",
  "remoteHandlers",
  "filesystemRead",
  "filesystemWrite",
  "executables",
  "networkAccess",
  "sudoRequirements",
  "outputFields",
] as const;

export type CapabilityField = (typeof CAPABILITY_FIELDS)[number];
export type DeclarationMode = "controlled" | "read-only";

export interface BuildCapabilityMode extends Record<CapabilityField, string[]> {}
export interface BuildCapabilityDeclaration {
  version: 1;
  build: string;
  modes: { controlled: BuildCapabilityMode; "read-only": BuildCapabilityMode };
}
export interface CapabilityFieldChange { field: CapabilityField; added: string[]; removed: string[] }
export interface CapabilityComparison {
  authorityExpanded: boolean;
  modes: Record<DeclarationMode, CapabilityFieldChange[]>;
}
export interface DeclarationBindingPayload {
  version: 1;
  mode: DeclarationMode;
  policyVersion: string;
  dispatcherSha256: string;
  declarationSha256: string;
  issuedAt: string;
  expiresAt: string;
}
export interface SignedDeclarationBinding { payload: string; signature: string }
export interface VerifiedDeclarationBinding { payload: DeclarationBindingPayload; hash: string }

const BUILD = /^[A-Za-z0-9._-]{1,128}$/;
const HASH = /^[a-f0-9]{64}$/;
const ENCODED = /^[A-Za-z0-9_-]{1,262144}$/;
const POLICY = /^[A-Za-z0-9._-]{1,64}$/;

function plain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const allowed = new Set(expected);
  if (Object.keys(value).some((key) => !allowed.has(key)) || expected.some((key) => !(key in value))) {
    throw new OpsHavenError("POLICY_DENIED", `${label} has an incompatible schema.`);
  }
}
function stringList(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length > 512) throw new OpsHavenError("POLICY_DENIED", `${label} must be a bounded array.`);
  const values = value.map((item) => {
    if (typeof item !== "string" || item.length === 0 || item.length > 256) throw new OpsHavenError("POLICY_DENIED", `${label} contains an invalid value.`);
    return item;
  });
  const sorted = [...values].sort();
  if (new Set(sorted).size !== sorted.length || values.some((item, index) => item !== sorted[index])) {
    throw new OpsHavenError("POLICY_DENIED", `${label} must be sorted and unique.`);
  }
  return values;
}
function mode(value: unknown, label: string): BuildCapabilityMode {
  if (!plain(value)) throw new OpsHavenError("POLICY_DENIED", `${label} is malformed.`);
  if (Object.keys(value).some((key) => !CAPABILITY_FIELDS.includes(key as CapabilityField)) || CAPABILITY_FIELDS.some((key) => !(key in value))) {
    throw new OpsHavenError("POLICY_DENIED", `${label} has an incompatible schema.`);
  }
  return Object.fromEntries(CAPABILITY_FIELDS.map((field) => [field, stringList(value[field], `${label}.${field}`)])) as unknown as BuildCapabilityMode;
}

export function parseCapabilityDeclaration(value: unknown): BuildCapabilityDeclaration {
  if (!plain(value) || value.version !== 1 || typeof value.build !== "string" || !BUILD.test(value.build) || !plain(value.modes)) {
    throw new OpsHavenError("POLICY_DENIED", "Capability declaration is malformed.");
  }
  exactKeys(value, ["version", "build", "modes"], "Capability declaration");
  exactKeys(value.modes, ["controlled", "read-only"], "Capability declaration modes");
  return { version: 1, build: value.build, modes: { controlled: mode(value.modes.controlled, "controlled declaration"), "read-only": mode(value.modes["read-only"], "read-only declaration") } };
}

export function capabilityDeclarationHash(declaration: BuildCapabilityDeclaration): string { return sha256(declaration); }
export function capabilityDeclarationPath(configPath: string): string { return `${configPath}.declaration.json`; }
export function declarationBindingPath(configPath: string): string { return `${configPath}.declaration-binding.json`; }

export async function loadCapabilityDeclaration(filePath: string): Promise<BuildCapabilityDeclaration> {
  const text = await readRegularTextFile(filePath, "Capability declaration", { maxBytes: 1048576, code: "POLICY_DENIED" });
  try { return parseCapabilityDeclaration(JSON.parse(text) as unknown); }
  catch (error) {
    if (error instanceof OpsHavenError) throw error;
    throw new OpsHavenError("POLICY_DENIED", "Capability declaration is invalid JSON.");
  }
}

export function compareCapabilityDeclarations(previous: BuildCapabilityDeclaration, current: BuildCapabilityDeclaration): CapabilityComparison {
  const modes = { controlled: [] as CapabilityFieldChange[], "read-only": [] as CapabilityFieldChange[] };
  let authorityExpanded = false;
  for (const modeName of ["controlled", "read-only"] as const) {
    for (const field of CAPABILITY_FIELDS) {
      const before = new Set(previous.modes[modeName][field]);
      const after = new Set(current.modes[modeName][field]);
      const added = [...after].filter((item) => !before.has(item)).sort();
      const removed = [...before].filter((item) => !after.has(item)).sort();
      if (added.length > 0) authorityExpanded = true;
      if (added.length || removed.length) modes[modeName].push({ field, added, removed });
    }
  }
  return { authorityExpanded, modes };
}

export function formatCapabilityComparison(comparison: CapabilityComparison): string {
  const lines: string[] = [];
  for (const modeName of ["controlled", "read-only"] as const) {
    lines.push(`${modeName}:`);
    if (!comparison.modes[modeName].length) lines.push("  no capability changes");
    for (const change of comparison.modes[modeName]) {
      for (const item of change.added) lines.push(`  + ${change.field}: ${item}`);
      for (const item of change.removed) lines.push(`  - ${change.field}: ${item}`);
    }
  }
  lines.push(comparison.authorityExpanded ? "Authority expansion requires a newly signed operator declaration binding." : "No authority expansion detected.");
  return `${lines.join("\n")}\n`;
}

export function buildDeclarationBinding(
  config: OpsHavenConfig,
  modeName: DeclarationMode,
  dispatcherSha256: string,
  declarationSha256: string,
  expiresAt: string,
  issuedAt = new Date().toISOString(),
): DeclarationBindingPayload {
  return { version: 1, mode: modeName, policyVersion: config.policyVersion, dispatcherSha256, declarationSha256, issuedAt, expiresAt };
}

function parseBindingPayload(value: unknown): DeclarationBindingPayload {
  if (!plain(value)) throw new OpsHavenError("POLICY_DENIED", "Declaration binding is malformed.");
  exactKeys(value, ["version", "mode", "policyVersion", "dispatcherSha256", "declarationSha256", "issuedAt", "expiresAt"], "Declaration binding");
  if (
    value.version !== 1
    || (value.mode !== "controlled" && value.mode !== "read-only")
    || typeof value.policyVersion !== "string"
    || !POLICY.test(value.policyVersion)
    || typeof value.dispatcherSha256 !== "string"
    || !HASH.test(value.dispatcherSha256)
    || typeof value.declarationSha256 !== "string"
    || !HASH.test(value.declarationSha256)
    || typeof value.issuedAt !== "string"
    || typeof value.expiresAt !== "string"
    || !Number.isFinite(Date.parse(value.issuedAt))
    || !Number.isFinite(Date.parse(value.expiresAt))
  ) throw new OpsHavenError("POLICY_DENIED", "Declaration binding is malformed.");
  return value as unknown as DeclarationBindingPayload;
}

function decodeCanonicalBase64Url(value: string, label: string): Uint8Array {
  const decoded = Buffer.from(value, "base64url");
  if (Buffer.from(decoded).toString("base64url") !== value) throw new OpsHavenError("POLICY_DENIED", `${label} is not canonically encoded.`);
  return decoded;
}

export function signDeclarationBinding(payload: DeclarationBindingPayload, privateKey: Uint8Array): SignedDeclarationBinding {
  const encoded = Buffer.from(canonicalize(payload), "utf8").toString("base64url");
  return { payload: encoded, signature: sign(null, Buffer.from(encoded, "utf8"), privateKey).toString("base64url") };
}

export function parseSignedDeclarationBinding(value: unknown): SignedDeclarationBinding {
  if (!plain(value)) throw new OpsHavenError("POLICY_DENIED", "Signed declaration binding is malformed.");
  exactKeys(value, ["payload", "signature"], "Signed declaration binding");
  if (typeof value.payload !== "string" || typeof value.signature !== "string" || !ENCODED.test(value.payload) || !ENCODED.test(value.signature)) {
    throw new OpsHavenError("POLICY_DENIED", "Signed declaration binding is malformed.");
  }
  decodeCanonicalBase64Url(value.payload, "Declaration binding payload");
  const signature = decodeCanonicalBase64Url(value.signature, "Declaration binding signature");
  if (signature.length !== 64) throw new OpsHavenError("POLICY_DENIED", "Declaration binding signature has an invalid length.");
  return { payload: value.payload, signature: value.signature };
}

export function verifyDeclarationBinding(
  config: OpsHavenConfig,
  binding: SignedDeclarationBinding,
  publicKey: Uint8Array,
  expectedMode: DeclarationMode,
  dispatcherSha256: string,
  declarationSha256: string,
  now = Date.now(),
): VerifiedDeclarationBinding {
  const parsed = parseSignedDeclarationBinding(binding);
  const signature = decodeCanonicalBase64Url(parsed.signature, "Declaration binding signature");
  if (!verify(null, Buffer.from(parsed.payload, "utf8"), publicKey, signature)) throw new OpsHavenError("POLICY_DENIED", "Declaration binding signature is invalid.");
  let decoded: unknown;
  try { decoded = JSON.parse(Buffer.from(decodeCanonicalBase64Url(parsed.payload, "Declaration binding payload")).toString("utf8")) as unknown; }
  catch { throw new OpsHavenError("POLICY_DENIED", "Declaration binding payload is malformed."); }
  const payload = parseBindingPayload(decoded);
  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  if (
    payload.mode !== expectedMode
    || payload.policyVersion !== config.policyVersion
    || payload.dispatcherSha256 !== dispatcherSha256
    || payload.declarationSha256 !== declarationSha256
    || issuedAt > now + 300000
    || expiresAt <= now
    || expiresAt <= issuedAt
    || expiresAt - issuedAt > 31536000000
  ) throw new OpsHavenError("POLICY_DENIED", "Declaration binding is inactive, expired, or mismatched.");
  return { payload, hash: sha256(payload) };
}

async function artifactHash(filePath: string): Promise<string> {
  return createHash("sha256").update(await readRegularFile(filePath, "Dispatcher artifact", { maxBytes: 16777216, code: "POLICY_DENIED" })).digest("hex");
}

export async function loadVerifiedDeclarationBinding(
  config: OpsHavenConfig,
  configPath: string,
  modeName: DeclarationMode,
  dispatcherPath: string,
): Promise<VerifiedDeclarationBinding> {
  const declaration = await loadCapabilityDeclaration(capabilityDeclarationPath(configPath));
  const bindingText = await readRegularTextFile(declarationBindingPath(configPath), "Signed declaration binding", { maxBytes: 1048576, code: "POLICY_DENIED" });
  let binding: unknown;
  try { binding = JSON.parse(bindingText) as unknown; }
  catch { throw new OpsHavenError("POLICY_DENIED", "Signed declaration binding is invalid JSON."); }
  const publicKey = await readRegularFile(config.approvals.verificationPublicKeyFile, "Operator declaration public key", { maxBytes: 65536, code: "POLICY_DENIED" });
  return verifyDeclarationBinding(config, parseSignedDeclarationBinding(binding), publicKey, modeName, await artifactHash(dispatcherPath), capabilityDeclarationHash(declaration));
}
