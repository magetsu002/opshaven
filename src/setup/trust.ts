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
import type { RemoteInstallResult } from "./install.js";
import type { RemoteSetupConfig } from "./remote.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export interface RemoteTrustReceipt {
  readonly ok: true;
  readonly dispatcherSha256: string;
  readonly capabilitySha256: string;
  readonly declarationSha256: string;
  readonly bindingSha256: string;
  readonly responsePublicKeySha256: string;
  readonly expiresAt: string;
  readonly installedPaths: readonly string[];
}

interface TrustMaterial {
  readonly capability: SignedCapabilityManifest;
  readonly declaration: unknown;
  readonly binding: SignedDeclarationBinding;
  readonly operatorPublicKey: Uint8Array;
  readonly dispatcherSha256: string;
  readonly declarationSha256: string;
  readonly expiresAt: string;
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

async function buildTrustMaterial(config: RemoteSetupConfig): Promise<TrustMaterial> {
  const remoteConfig = await loadConfig(`${config.policyConfigPath}.dispatcher.json`);
  const dispatcherSha256 = await dispatcherArtifactSha256(config.local.dispatcherPath);
  const declaration = await loadCapabilityDeclaration(config.local.capabilityDeclarationPath);
  const declarationSha256 = capabilityDeclarationHash(declaration);
  const operatorPrivateKey = await fs.readFile(config.local.operatorPrivateKeyFile);
  const operatorPublicKey = await fs.readFile(config.local.operatorPublicKeyFile);
  assertKeyPair(operatorPrivateKey, operatorPublicKey);
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + config.trust.expiresInSeconds * 1000).toISOString();
  const capability = signCapabilityManifest(buildCapabilityPayload(remoteConfig, "read-only", dispatcherSha256, expiresAt, issuedAt.toISOString()), operatorPrivateKey);
  const binding = signDeclarationBinding(buildDeclarationBinding(remoteConfig, "read-only", dispatcherSha256, declarationSha256, expiresAt, issuedAt.toISOString()), operatorPrivateKey);
  verifyCapabilityManifest(remoteConfig, capability, operatorPublicKey, "read-only", dispatcherSha256, issuedAt.getTime());
  verifyDeclarationBinding(remoteConfig, binding, operatorPublicKey, "read-only", dispatcherSha256, declarationSha256, issuedAt.getTime());
  return Object.freeze({ capability, declaration, binding, operatorPublicKey, dispatcherSha256, declarationSha256, expiresAt });
}

function installScript(config: RemoteSetupConfig, remoteStage: string): string {
  const paths = {
    stage: remoteStage,
    config: config.remote.configPath,
    publicKey: "/etc/opshaven/approval-public.pem",
    capability: `${config.remote.configPath}.capability.json`,
    declaration: `${config.remote.configPath}.declaration.json`,
    binding: `${config.remote.configPath}.declaration-binding.json`,
    responsePrivate: `${config.remote.configPath}.response-private.pem`,
    responsePublic: `${config.remote.configPath}.response-public.pem`,
  };
  return `import hashlib, json, os, pathlib, shutil, stat, subprocess, tempfile\npaths=json.loads(${JSON.stringify(JSON.stringify(paths))})\nos.umask(0o077)\ndef fail(message): raise RuntimeError(message)\ndef regular(path, maximum=1048576):\n    info=os.lstat(path)\n    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > maximum: fail('unsafe trust file')\ndef atomic_copy(source, destination, mode):\n    regular(source)\n    parent=pathlib.Path(destination).parent\n    info=os.lstat(parent)\n    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode): fail('unsafe trust destination')\n    descriptor, temporary=tempfile.mkstemp(prefix='.opshaven-trust-', dir=parent)\n    try:\n        with os.fdopen(descriptor, 'wb') as output, open(source, 'rb') as input_handle:\n            shutil.copyfileobj(input_handle, output, 1048576)\n            output.flush(); os.fsync(output.fileno())\n        os.chmod(temporary, mode); os.chown(temporary, 0, 0); os.replace(temporary, destination)\n    finally:\n        if os.path.exists(temporary): os.unlink(temporary)\nstage=pathlib.Path(paths['stage'])\nif not stage.is_absolute() or stage.parent != pathlib.Path('/tmp') or stage.is_symlink() or not stage.is_dir(): fail('invalid trust stage')\nfor name, destination, mode in (\n    ('operator-public.pem', paths['publicKey'], 0o644),\n    ('capability.json', paths['capability'], 0o600),\n    ('declaration.json', paths['declaration'], 0o644),\n    ('binding.json', paths['binding'], 0o600),\n): atomic_copy(stage / name, destination, mode)\nif not os.path.exists(paths['responsePrivate']):\n    result=subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','Ed25519','-out',paths['responsePrivate']], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)\n    if result.returncode != 0: fail('response private key generation failed')\nos.chmod(paths['responsePrivate'], 0o600); os.chown(paths['responsePrivate'], 0, 0)\nresult=subprocess.run(['/usr/bin/openssl','pkey','-in',paths['responsePrivate'],'-pubout','-out',paths['responsePublic']], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)\nif result.returncode != 0: fail('response public key generation failed')\nos.chmod(paths['responsePublic'], 0o644); os.chown(paths['responsePublic'], 0, 0)\nevidence={}\nfor key in ('publicKey','capability','declaration','binding','responsePublic'):\n    file_path=paths[key]; regular(file_path); evidence[key]=hashlib.sha256(open(file_path,'rb').read()).hexdigest()\nprint(json.dumps({'ok':True,'hashes':evidence,'responsePublic':paths['responsePublic']}, sort_keys=True))\nshutil.rmtree(stage)\n`;
}

function parseRemoteEvidence(stdout: string): { hashes: Record<string, string>; responsePublic: string } {
  let value: unknown;
  try { value = JSON.parse(stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust installer returned invalid JSON."); }
  if (!value || typeof value !== "object") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust evidence is malformed.");
  const record = value as Record<string, any>;
  if (record.ok !== true || !record.hashes || typeof record.responsePublic !== "string") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust evidence is incomplete.");
  const hashes: Record<string, string> = {};
  for (const key of ["publicKey", "capability", "declaration", "binding", "responsePublic"]) {
    const digest = record.hashes[key];
    if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote trust hash evidence is invalid.");
    hashes[key] = digest;
  }
  if (record.responsePublic !== "/etc/opshaven/config.json.response-public.pem") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote response public-key path is unexpected.");
  return { hashes, responsePublic: record.responsePublic };
}

export async function provisionRemoteTrust(
  config: RemoteSetupConfig,
  install: RemoteInstallResult,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteTrustReceipt> {
  if (!install.ok || !/^[a-f0-9]{64}$/.test(install.runtimeTreeSha256)) throw new OpsHavenError("POLICY_DENIED", "Trust provisioning requires verified runtime installation evidence.");
  const material = await buildTrustMaterial(config);
  if (material.dispatcherSha256 !== createHash("sha256").update(await fs.readFile(config.local.dispatcherPath)).digest("hex")) throw new OpsHavenError("POLICY_DENIED", "Dispatcher changed during trust generation.");
  const stage = await fs.mkdtemp(path.join(tmpdir(), "opshaven-trust-"));
  const remoteStage = `/tmp/${path.basename(stage)}`;
  const capabilityText = `${JSON.stringify(material.capability)}\n`;
  const declarationText = `${JSON.stringify(material.declaration)}\n`;
  const bindingText = `${JSON.stringify(material.binding)}\n`;
  try {
    await Promise.all([
      fs.writeFile(path.join(stage, "operator-public.pem"), material.operatorPublicKey, { mode: 0o600 }),
      fs.writeFile(path.join(stage, "capability.json"), capabilityText, { mode: 0o600 }),
      fs.writeFile(path.join(stage, "declaration.json"), declarationText, { mode: 0o600 }),
      fs.writeFile(path.join(stage, "binding.json"), bindingText, { mode: 0o600 }),
    ]);
    const uploaded = await transport.upload(stage, "/tmp", true);
    if (uploaded.code !== 0) throw new OpsHavenError("SSH_FAILED", "Remote trust upload failed.", true);
    const installed = await transport.runPython(installScript(config, remoteStage), true);
    if (installed.code !== 0) throw new OpsHavenError("SSH_FAILED", `Remote trust installation failed safely: ${installed.stderr.trim() || "no diagnostic"}.`, true);
    const evidence = parseRemoteEvidence(installed.stdout);
    const expected = {
      publicKey: hashBytes(material.operatorPublicKey),
      capability: hashBytes(capabilityText),
      declaration: hashBytes(declarationText),
      binding: hashBytes(bindingText),
    };
    for (const [key, digest] of Object.entries(expected)) if (evidence.hashes[key] !== digest) throw new OpsHavenError("POLICY_DENIED", `Installed ${key} trust material does not match local verified material.`);
    const localResponsePublic = `${config.policyConfigPath}.response-public.pem`;
    const downloaded = await transport.download(evidence.responsePublic, localResponsePublic);
    if (downloaded.code !== 0) throw new OpsHavenError("SSH_FAILED", "Response public-key download failed.", true);
    const responsePublic = await fs.readFile(localResponsePublic);
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
      dispatcherSha256: material.dispatcherSha256,
      capabilitySha256: expected.capability,
      declarationSha256: material.declarationSha256,
      bindingSha256: expected.binding,
      responsePublicKeySha256: evidence.hashes.responsePublic,
      expiresAt: material.expiresAt,
      installedPaths: Object.freeze([
        "/etc/opshaven/approval-public.pem",
        `${config.remote.configPath}.capability.json`,
        `${config.remote.configPath}.declaration.json`,
        `${config.remote.configPath}.declaration-binding.json`,
        `${config.remote.configPath}.response-private.pem`,
        `${config.remote.configPath}.response-public.pem`,
      ]),
    });
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}
