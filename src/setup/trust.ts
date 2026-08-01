import { createHash, createPublicKey } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  buildCapabilityPayload,
  dispatcherArtifactSha256,
  signCapabilityManifest,
  verifyCapabilityManifest,
  type SignedCapabilityManifest,
} from "../capabilities.js";
import {
  buildDeclarationBinding,
  capabilityDeclarationHash,
  loadCapabilityDeclaration,
  signDeclarationBinding,
  verifyDeclarationBinding,
  type SignedDeclarationBinding,
} from "../capability-declaration.js";
import { loadConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { readRegularFile } from "../safe-fs.js";
import type { RemoteInstallResult } from "./install.js";
import type { RemoteSetupConfig } from "./remote.js";
import { buildDesiredRemoteState, SETUP_DISPATCHER_MODE, type DesiredRemoteState } from "./state.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export interface RemoteTrustReceipt {
  readonly ok: true;
  readonly mode?: "controlled";
  readonly dispatcherSha256: string;
  readonly capabilitySha256: string;
  readonly capabilityIdentitySha256?: string;
  readonly policySha256?: string;
  readonly applicationScopeSha256?: string;
  readonly declarationSha256: string;
  readonly bindingSha256: string;
  readonly responsePublicKeySha256: string;
  readonly expiresAt: string;
  readonly installedPaths: readonly string[];
  readonly changed?: readonly string[];
}

interface TrustMaterial {
  readonly capability: SignedCapabilityManifest;
  readonly declaration: unknown;
  readonly binding: SignedDeclarationBinding;
  readonly operatorPublicKey: Uint8Array;
  readonly dispatcherSha256: string;
  readonly declarationSha256: string;
  readonly expiresAt: string;
  readonly desired: DesiredRemoteState;
}

function exportedPublicKey(value: unknown): string {
  return String((value as any).export({ type: "spki", format: "pem" })).replace(/\r\n/g, "\n").trim();
}

function assertKeyPair(privateKey: Uint8Array, publicKey: Uint8Array): void {
  try {
    const derived = exportedPublicKey(createPublicKey(privateKey));
    const declared = exportedPublicKey(createPublicKey(publicKey));
    if (derived !== declared) throw new Error("mismatch");
  } catch {
    throw new OpsHavenError("POLICY_DENIED", "Operator signing private and public keys do not correspond.");
  }
}

function hashBytes(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function atomicWrite(filePath: string, value: Uint8Array | string, mode: number): Promise<void> {
  const temporary = `${filePath}.opshaven-${process.pid}-${Date.now()}`;
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  try {
    await fs.writeFile(temporary, value, { mode });
    await fs.chmod(temporary, mode);
    await fs.rename(temporary, filePath);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

async function buildTrustMaterial(config: RemoteSetupConfig, desiredInput?: DesiredRemoteState): Promise<TrustMaterial> {
  const remoteConfig = await loadConfig(`${config.policyConfigPath}.dispatcher.json`);
  const desired = desiredInput ?? await buildDesiredRemoteState(config);
  const dispatcherSha256 = await dispatcherArtifactSha256(config.local.dispatcherPath);
  if (dispatcherSha256 !== desired.dispatcherSha256) throw new OpsHavenError("POLICY_DENIED", "Desired dispatcher identity changed before authorization generation.");
  const declaration = await loadCapabilityDeclaration(config.local.capabilityDeclarationPath);
  const declarationSha256 = capabilityDeclarationHash(declaration);
  if (declarationSha256 !== desired.declarationSha256) throw new OpsHavenError("POLICY_DENIED", "Desired declaration identity changed before authorization generation.");
  const operatorPrivateKey = await readRegularFile(config.local.operatorPrivateKeyFile, "Operator signing private key", { ownerOnly: true, maxBytes: 1048576, code: "POLICY_DENIED" });
  const operatorPublicKey = await readRegularFile(config.local.operatorPublicKeyFile, "Operator signing public key", { maxBytes: 1048576, code: "POLICY_DENIED" });
  assertKeyPair(operatorPrivateKey, operatorPublicKey);
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + config.trust.expiresInSeconds * 1000).toISOString();
  const capability = signCapabilityManifest(buildCapabilityPayload(remoteConfig, SETUP_DISPATCHER_MODE, dispatcherSha256, expiresAt, issuedAt.toISOString()), operatorPrivateKey);
  const binding = signDeclarationBinding(buildDeclarationBinding(remoteConfig, SETUP_DISPATCHER_MODE, dispatcherSha256, declarationSha256, expiresAt, issuedAt.toISOString()), operatorPrivateKey);
  verifyCapabilityManifest(remoteConfig, capability, operatorPublicKey, SETUP_DISPATCHER_MODE, dispatcherSha256, issuedAt.getTime());
  verifyDeclarationBinding(remoteConfig, binding, operatorPublicKey, SETUP_DISPATCHER_MODE, dispatcherSha256, declarationSha256, issuedAt.getTime());
  return Object.freeze({ capability, declaration, binding, operatorPublicKey, dispatcherSha256, declarationSha256, expiresAt, desired });
}

function parseRemoteEvidence(stdout: string): { hashes: Record<string, string>; responsePublic: string; changed: string[] } {
  let value: unknown;
  try { value = JSON.parse(stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust installer returned invalid JSON."); }
  if (!value || typeof value !== "object") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust evidence is malformed.");
  const record = value as Record<string, any>;
  if (record.ok !== true || !record.hashes || typeof record.responsePublic !== "string" || !Array.isArray(record.changed)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust evidence is incomplete.");
  const hashes: Record<string, string> = {};
  for (const key of ["config", "publicKey", "capability", "declaration", "binding", "responsePublic"]) {
    const digest = record.hashes[key];
    if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust hash evidence is invalid.");
    hashes[key] = digest;
  }
  if (record.responsePublic !== "/etc/opshaven/config.json.response-public.pem") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote response public-key path is unexpected.");
  const changed = record.changed.map((item: unknown) => {
    if (typeof item !== "string" || !item.startsWith("/")) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust changed-path evidence is invalid.");
    return item;
  });
  return { hashes, responsePublic: record.responsePublic, changed };
}

export async function provisionRemoteTrust(
  config: RemoteSetupConfig,
  install: RemoteInstallResult,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
  desiredInput?: DesiredRemoteState,
): Promise<RemoteTrustReceipt> {
  if (!install.ok || !/^[a-f0-9]{64}$/.test(install.runtimeTreeSha256) || !/^\/var\/lib\/opshaven\/backups\/[A-Za-z0-9]+$/.test(install.backupRoot)) throw new OpsHavenError("POLICY_DENIED", "Trust provisioning requires verified runtime installation and backup evidence.");
  const material = await buildTrustMaterial(config, desiredInput);
  if (material.dispatcherSha256 !== await dispatcherArtifactSha256(config.local.dispatcherPath)) throw new OpsHavenError("POLICY_DENIED", "Dispatcher changed during trust generation.");
  const stage = await fs.mkdtemp(path.join(tmpdir(), "opshaven-trust-"));
  const remoteStage = `/tmp/${path.basename(stage)}`;
  const capabilityText = `${JSON.stringify(material.capability)}\n`;
  const declarationText = `${JSON.stringify(material.declaration)}\n`;
  const bindingText = `${JSON.stringify(material.binding)}\n`;
  const remoteConfigPath = `${config.policyConfigPath}.dispatcher.json`;
  const remoteConfigText = await fs.readFile(remoteConfigPath, "utf8");
  const plan = Object.freeze({ version: 1, stageRoot: remoteStage, backupRoot: install.backupRoot, receiptPath: config.remote.receiptPath, receiptId: install.receiptId, sourceSha: config.expectedSourceSha });
  try {
    await Promise.all([
      fs.writeFile(path.join(stage, "remote-config.json"), remoteConfigText, { mode: 0o600 }),
      fs.writeFile(path.join(stage, "operator-public.pem"), material.operatorPublicKey, { mode: 0o600 }),
      fs.writeFile(path.join(stage, "capability.json"), capabilityText, { mode: 0o600 }),
      fs.writeFile(path.join(stage, "declaration.json"), declarationText, { mode: 0o600 }),
      fs.writeFile(path.join(stage, "binding.json"), bindingText, { mode: 0o600 }),
      fs.writeFile(path.join(stage, "trust-plan.json"), `${JSON.stringify(plan)}\n`, { mode: 0o600 }),
      fs.copyFile(path.join(process.cwd(), "packaging", "remote-trust-installer.py"), path.join(stage, "installer.py")),
    ]);
    const uploaded = await transport.upload(stage, "/tmp", true);
    if (uploaded.code !== 0) throw new OpsHavenError("SSH_FAILED", "Remote trust upload failed.", true);
    const installed = await transport.runPrivileged(["/usr/bin/python3", `${remoteStage}/installer.py`, remoteStage], { timeoutMs: 120000, maximumBytes: 1048576 });
    if (installed.code !== 0) throw new OpsHavenError("SSH_FAILED", `Remote trust installation failed safely: ${installed.stderr.trim() || "no diagnostic"}.`, true);
    const evidence = parseRemoteEvidence(installed.stdout);
    const expected = { config: hashBytes(remoteConfigText), publicKey: hashBytes(material.operatorPublicKey), capability: hashBytes(capabilityText), declaration: hashBytes(declarationText), binding: hashBytes(bindingText) };
    for (const [key, digest] of Object.entries(expected)) if (evidence.hashes[key] !== digest) throw new OpsHavenError("POLICY_DENIED", `Installed ${key} trust material does not match local verified material.`);
    const localResponsePublic = `${config.policyConfigPath}.response-public.pem`;
    const downloaded = await transport.download(evidence.responsePublic, localResponsePublic);
    if (downloaded.code !== 0) throw new OpsHavenError("SSH_FAILED", "Response public-key download failed.", true);
    const responsePublic = await readRegularFile(localResponsePublic, "Downloaded response public key", { maxBytes: 1048576, code: "POLICY_DENIED" });
    if (hashBytes(responsePublic) !== evidence.hashes.responsePublic) throw new OpsHavenError("POLICY_DENIED", "Downloaded response public key does not match remote evidence.");
    createPublicKey(responsePublic);
    await Promise.all([
      atomicWrite(`${config.policyConfigPath}.capability.json`, capabilityText, 0o600),
      atomicWrite(`${config.policyConfigPath}.declaration.json`, declarationText, 0o600),
      atomicWrite(`${config.policyConfigPath}.declaration-binding.json`, bindingText, 0o600),
      atomicWrite(config.local.operatorPublicKeyFile, material.operatorPublicKey, 0o644),
      fs.chmod(localResponsePublic, 0o644),
    ]);
    return Object.freeze({
      ok: true,
      mode: SETUP_DISPATCHER_MODE,
      dispatcherSha256: material.dispatcherSha256,
      capabilitySha256: expected.capability,
      capabilityIdentitySha256: material.desired.capabilityIdentitySha256,
      policySha256: material.desired.policySha256,
      applicationScopeSha256: material.desired.applicationScopeSha256,
      declarationSha256: material.declarationSha256,
      bindingSha256: expected.binding,
      responsePublicKeySha256: evidence.hashes.responsePublic,
      expiresAt: material.expiresAt,
      installedPaths: Object.freeze([config.remote.configPath, "/etc/opshaven/approval-public.pem", `${config.remote.configPath}.capability.json`, `${config.remote.configPath}.declaration.json`, `${config.remote.configPath}.declaration-binding.json`, `${config.remote.configPath}.response-private.pem`, `${config.remote.configPath}.response-public.pem`]),
      changed: Object.freeze(evidence.changed),
    });
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}
