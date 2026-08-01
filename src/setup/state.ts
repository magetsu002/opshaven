import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { buildCapabilityPayload, dispatcherArtifactSha256 } from "../capabilities.js";
import { capabilityDeclarationHash, loadCapabilityDeclaration } from "../capability-declaration.js";
import { sha256 } from "../canonical.js";
import { loadConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { readRegularFile } from "../safe-fs.js";
import { buildRuntimeManifest } from "./install.js";
import type { RemoteSetupConfig } from "./remote.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export const REMOTE_STATE_SCHEMA_VERSION = 2 as const;
export const SETUP_DISPATCHER_MODE = "controlled" as const;
export const REMOTE_STATE_PATH = "/var/lib/opshaven/remote-state.json" as const;

export type RemoteSetupChangeType =
  | "NO_CHANGE"
  | "AUTHORIZATION_ONLY"
  | "APPLICATION_DECLARATION_ONLY"
  | "RUNTIME_UPDATE"
  | "DISPATCHER_UPDATE"
  | "FULL_INSTALL"
  | "REPAIR_REQUIRED";

export interface DesiredRemoteState {
  readonly schemaVersion: 2;
  readonly sourceSha: string;
  readonly dispatcherMode: "controlled";
  readonly runtimeSha256: string;
  readonly dispatcherSha256: string;
  readonly policySha256: string;
  readonly capabilityIdentitySha256: string;
  readonly declarationSha256: string;
  readonly operatorVerificationIdentity: string;
  readonly applicationScope: readonly string[];
  readonly applicationScopeSha256: string;
}

export interface InstalledRemoteState {
  readonly status: "absent" | "complete" | "inconsistent";
  readonly source: "installed remote state";
  readonly schemaVersion: number | null;
  readonly generation: number | null;
  readonly sourceSha: string | null;
  readonly dispatcherMode: "controlled" | "read-only" | null;
  readonly runtimeSha256: string | null;
  readonly dispatcherSha256: string | null;
  readonly policySha256: string | null;
  readonly capabilityIdentitySha256: string | null;
  readonly capabilityArtifactSha256: string | null;
  readonly declarationSha256: string | null;
  readonly operatorVerificationIdentity: string | null;
  readonly applicationScope: readonly string[];
  readonly applicationScopeSha256: string | null;
  readonly platform: string | null;
  readonly architecture: string | null;
  readonly detail?: string;
}

export interface RemoteStateComparison {
  readonly desired: DesiredRemoteState;
  readonly installed: InstalledRemoteState;
  readonly changeType: RemoteSetupChangeType;
  readonly reasons: readonly string[];
  readonly compatible: boolean;
}

function digestBytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function capabilityIdentity(payload: ReturnType<typeof buildCapabilityPayload>): string {
  const { issuedAt: _issuedAt, expiresAt: _expiresAt, ...stable } = payload;
  return sha256(stable);
}

export async function buildDesiredRemoteState(config: RemoteSetupConfig): Promise<DesiredRemoteState> {
  const remotePolicyPath = `${config.policyConfigPath}.dispatcher.json`;
  const [remoteConfig, runtime, declaration, operatorPublic, policyText] = await Promise.all([
    loadConfig(remotePolicyPath),
    buildRuntimeManifest(config.local.runtimeRoot),
    loadCapabilityDeclaration(config.local.capabilityDeclarationPath),
    readRegularFile(config.local.operatorPublicKeyFile, "Operator verification public key", { maxBytes: 1048576, code: "POLICY_DENIED" }),
    fs.readFile(remotePolicyPath, "utf8"),
  ]);
  let policyDocument: unknown;
  try { policyDocument = JSON.parse(policyText) as unknown; }
  catch { throw new OpsHavenError("CONFIG_INVALID", "Remote deployment policy is not valid JSON."); }
  const dispatcherSha256 = await dispatcherArtifactSha256(config.local.dispatcherPath);
  const identityPayload = buildCapabilityPayload(
    remoteConfig,
    SETUP_DISPATCHER_MODE,
    dispatcherSha256,
    "2100-01-01T00:00:00.000Z",
    "2000-01-01T00:00:00.000Z",
  );
  const applicationScope = [...remoteConfig.resources.values()]
    .filter((resource) => resource.kind === "application")
    .map((resource) => resource.id)
    .sort();
  return Object.freeze({
    schemaVersion: REMOTE_STATE_SCHEMA_VERSION,
    sourceSha: config.expectedSourceSha,
    dispatcherMode: SETUP_DISPATCHER_MODE,
    runtimeSha256: runtime.treeSha256,
    dispatcherSha256,
    policySha256: sha256(policyDocument),
    capabilityIdentitySha256: capabilityIdentity(identityPayload),
    declarationSha256: capabilityDeclarationHash(declaration),
    operatorVerificationIdentity: digestBytes(operatorPublic),
    applicationScope: Object.freeze(applicationScope),
    applicationScopeSha256: sha256(applicationScope),
  });
}

function stateInspectionScript(config: RemoteSetupConfig): string {
  const values = JSON.stringify({
    receipt: config.remote.receiptPath,
    state: REMOTE_STATE_PATH,
    runtimeManifest: `${config.remote.stateDirectory}/runtime-manifest.json`,
    runtimeRoot: config.remote.runtimeRoot,
    config: config.remote.configPath,
    capability: `${config.remote.configPath}.capability.json`,
    declaration: `${config.remote.configPath}.declaration.json`,
    publicKey: "/etc/opshaven/approval-public.pem",
  });
  return `import base64, hashlib, json, os, pathlib, platform, stat\nP=json.loads(${JSON.stringify(values)})\ndef regular(path, maximum=16777216):\n    p=pathlib.Path(path)\n    try: info=os.lstat(p)\n    except OSError: return False\n    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_size <= maximum\ndef read_json(path):\n    if not regular(path, 2097152): raise RuntimeError('missing or unsafe state artifact')\n    with open(path,'r',encoding='utf-8') as handle: return json.load(handle)\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef digest_bytes(path):\n    if not regular(path): raise RuntimeError('missing or unsafe state artifact')\n    h=hashlib.sha256()\n    with open(path,'rb') as handle:\n        while True:\n            chunk=handle.read(1048576)\n            if not chunk: break\n            h.update(chunk)\n    return h.hexdigest()\ndef digest_json(value): return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()\nif not regular(P['receipt'], 2097152):\n    print(canonical({'status':'absent','source':'installed remote state'})); raise SystemExit(0)\ntry:\n    receipt=read_json(P['receipt'])\n    capability_document=read_json(P['capability'])\n    encoded=capability_document.get('payload','')\n    if not isinstance(encoded,str): raise RuntimeError('capability payload is missing')\n    padding='='*((4-len(encoded)%4)%4)\n    capability=json.loads(base64.urlsafe_b64decode((encoded+padding).encode('ascii')).decode('utf-8'))\n    stable={key:value for key,value in capability.items() if key not in ('issuedAt','expiresAt')}\n    policy=read_json(P['config'])\n    declaration=read_json(P['declaration'])\n    manifest=read_json(P['runtimeManifest'])\n    controlled=f"{P['runtimeRoot']}/src/remote/dispatcher.js"\n    readonly=f"{P['runtimeRoot']}/src/remote/read-only-dispatcher.js"\n    dispatcher=controlled if regular(controlled) else readonly if regular(readonly) else None\n    if dispatcher is None: raise RuntimeError('installed dispatcher is missing')\n    applications=sorted([item.get('id') for item in policy.get('resources',[]) if isinstance(item,dict) and item.get('kind')=='application' and isinstance(item.get('id'),str)])\n    recorded=read_json(P['state']) if regular(P['state'], 2097152) else {}\n    actual={\n      'status':'complete','source':'installed remote state',\n      'schemaVersion':recorded.get('schemaVersion',1),\n      'generation':recorded.get('generation'),\n      'sourceSha':receipt.get('sourceSha'),\n      'dispatcherMode':capability.get('mode'),\n      'runtimeSha256':manifest.get('treeSha256') or receipt.get('runtimeTreeSha256'),\n      'dispatcherSha256':digest_bytes(dispatcher),\n      'policySha256':digest_json(policy),\n      'capabilityIdentitySha256':digest_json(stable),\n      'capabilityArtifactSha256':digest_bytes(P['capability']),\n      'declarationSha256':digest_json(declaration),\n      'operatorVerificationIdentity':digest_bytes(P['publicKey']),\n      'applicationScope':applications,\n      'applicationScopeSha256':digest_json(applications),\n      'platform':platform.system(),\n      'architecture':platform.machine(),\n    }\n    if recorded:\n      for key in ('dispatcherMode','runtimeSha256','dispatcherSha256','policySha256','capabilityIdentitySha256','declarationSha256','operatorVerificationIdentity','applicationScopeSha256'):\n        if recorded.get(key) != actual.get(key):\n          actual={'status':'inconsistent','source':'installed remote state','schemaVersion':recorded.get('schemaVersion'),'generation':recorded.get('generation'),'sourceSha':receipt.get('sourceSha'),'dispatcherMode':actual.get('dispatcherMode'),'runtimeSha256':actual.get('runtimeSha256'),'dispatcherSha256':actual.get('dispatcherSha256'),'policySha256':actual.get('policySha256'),'capabilityIdentitySha256':actual.get('capabilityIdentitySha256'),'capabilityArtifactSha256':actual.get('capabilityArtifactSha256'),'declarationSha256':actual.get('declarationSha256'),'operatorVerificationIdentity':actual.get('operatorVerificationIdentity'),'applicationScope':applications,'applicationScopeSha256':actual.get('applicationScopeSha256'),'platform':platform.system(),'architecture':platform.machine(),'detail':'recorded remote state does not match installed artifacts'}\n          break\n    print(canonical(actual))\nexcept Exception as error:\n    print(canonical({'status':'inconsistent','source':'installed remote state','schemaVersion':None,'generation':None,'sourceSha':None,'dispatcherMode':None,'runtimeSha256':None,'dispatcherSha256':None,'policySha256':None,'capabilityIdentitySha256':None,'capabilityArtifactSha256':None,'declarationSha256':None,'operatorVerificationIdentity':None,'applicationScope':[],'applicationScopeSha256':None,'platform':platform.system(),'architecture':platform.machine(),'detail':str(error)[:200]}))\n`;
}

function optionalString(value: unknown, pattern: RegExp): string | null {
  return typeof value === "string" && pattern.test(value) ? value : null;
}

export async function readInstalledRemoteState(
  config: RemoteSetupConfig,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<InstalledRemoteState> {
  const result = await transport.runPython(stateInspectionScript(config), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Installed remote state could not be inspected safely.", true);
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Installed remote state response is not valid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Installed remote state response is malformed.");
  const record = value as Record<string, unknown>;
  if (record.status === "absent") {
    return Object.freeze({
      status: "absent", source: "installed remote state", schemaVersion: null, generation: null, sourceSha: null,
      dispatcherMode: null, runtimeSha256: null, dispatcherSha256: null, policySha256: null,
      capabilityIdentitySha256: null, capabilityArtifactSha256: null, declarationSha256: null,
      operatorVerificationIdentity: null, applicationScope: Object.freeze([]), applicationScopeSha256: null,
      platform: null, architecture: null,
    });
  }
  if (record.status !== "complete" && record.status !== "inconsistent") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Installed remote state status is invalid.");
  const applications = Array.isArray(record.applicationScope)
    ? record.applicationScope.filter((item): item is string => typeof item === "string" && /^[a-z][a-z0-9._-]{0,63}$/.test(item)).sort()
    : [];
  const mode = record.dispatcherMode === "controlled" || record.dispatcherMode === "read-only" ? record.dispatcherMode : null;
  return Object.freeze({
    status: record.status,
    source: "installed remote state",
    schemaVersion: Number.isInteger(record.schemaVersion) ? record.schemaVersion as number : null,
    generation: Number.isInteger(record.generation) ? record.generation as number : null,
    sourceSha: optionalString(record.sourceSha, /^[a-f0-9]{40}$/),
    dispatcherMode: mode,
    runtimeSha256: optionalString(record.runtimeSha256, /^[a-f0-9]{64}$/),
    dispatcherSha256: optionalString(record.dispatcherSha256, /^[a-f0-9]{64}$/),
    policySha256: optionalString(record.policySha256, /^[a-f0-9]{64}$/),
    capabilityIdentitySha256: optionalString(record.capabilityIdentitySha256, /^[a-f0-9]{64}$/),
    capabilityArtifactSha256: optionalString(record.capabilityArtifactSha256, /^[a-f0-9]{64}$/),
    declarationSha256: optionalString(record.declarationSha256, /^[a-f0-9]{64}$/),
    operatorVerificationIdentity: optionalString(record.operatorVerificationIdentity, /^[a-f0-9]{64}$/),
    applicationScope: Object.freeze(applications),
    applicationScopeSha256: optionalString(record.applicationScopeSha256, /^[a-f0-9]{64}$/),
    platform: typeof record.platform === "string" ? record.platform.slice(0, 64) : null,
    architecture: typeof record.architecture === "string" ? record.architecture.slice(0, 64) : null,
    ...(typeof record.detail === "string" ? { detail: record.detail.slice(0, 200) } : {}),
  });
}

export function compareRemoteState(desired: DesiredRemoteState, installed: InstalledRemoteState): RemoteStateComparison {
  if (installed.status === "absent") return Object.freeze({ desired, installed, changeType: "FULL_INSTALL", reasons: Object.freeze(["no installed runtime state was found"]), compatible: false });
  if (installed.status === "inconsistent") return Object.freeze({ desired, installed, changeType: "REPAIR_REQUIRED", reasons: Object.freeze([installed.detail ?? "installed state is incomplete or inconsistent"]), compatible: false });
  const reasons: string[] = [];
  let changeType: RemoteSetupChangeType = "NO_CHANGE";
  if (installed.dispatcherMode !== desired.dispatcherMode) {
    changeType = "DISPATCHER_UPDATE";
    reasons.push(`dispatcher mode is ${installed.dispatcherMode ?? "unknown"}, expected ${desired.dispatcherMode}`);
  }
  if (installed.runtimeSha256 !== desired.runtimeSha256) {
    changeType = changeType === "DISPATCHER_UPDATE" ? "DISPATCHER_UPDATE" : "RUNTIME_UPDATE";
    reasons.push("runtime artifact identity differs");
  }
  if (installed.dispatcherSha256 !== desired.dispatcherSha256) {
    changeType = "DISPATCHER_UPDATE";
    reasons.push("dispatcher artifact identity differs");
  }
  const authorizationDiffers = installed.policySha256 !== desired.policySha256
    || installed.capabilityIdentitySha256 !== desired.capabilityIdentitySha256
    || installed.operatorVerificationIdentity !== desired.operatorVerificationIdentity
    || installed.applicationScopeSha256 !== desired.applicationScopeSha256;
  if (changeType === "NO_CHANGE" && authorizationDiffers) {
    changeType = "AUTHORIZATION_ONLY";
    reasons.push("signed authorization or application scope differs");
  }
  if (changeType === "NO_CHANGE" && installed.declarationSha256 !== desired.declarationSha256) {
    changeType = "APPLICATION_DECLARATION_ONLY";
    reasons.push("reviewed application declaration differs");
  }
  if (changeType === "NO_CHANGE" && (installed.schemaVersion ?? 0) < desired.schemaVersion) {
    changeType = "APPLICATION_DECLARATION_ONLY";
    reasons.push("legacy installed state requires explicit manifest migration");
  }
  return Object.freeze({ desired, installed, changeType, reasons: Object.freeze(reasons), compatible: changeType === "NO_CHANGE" });
}

export async function prepareRemoteState(
  config: RemoteSetupConfig,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteStateComparison> {
  const [desired, installed] = await Promise.all([buildDesiredRemoteState(config), readInstalledRemoteState(config, transport)]);
  return compareRemoteState(desired, installed);
}

function stateRecordScript(desired: DesiredRemoteState, boundarySha256: string): string {
  const payload = JSON.stringify({ path: REMOTE_STATE_PATH, desired, boundarySha256 });
  return `import json, os, pathlib, tempfile\nrequest=json.loads(${JSON.stringify(payload)})\npath=pathlib.Path(request['path'])\nprevious={}\ntry:\n    with open(path,'r',encoding='utf-8') as handle: previous=json.load(handle)\nexcept (OSError,ValueError): pass\nstate=dict(request['desired'])\nstate['generation']=int(previous.get('generation',0))+1\nstate['boundarySha256']=request['boundarySha256']\nstate['recordedAt']=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat().replace('+00:00','Z')\npath.parent.mkdir(parents=True,exist_ok=True)\ndescriptor,temporary=tempfile.mkstemp(prefix='.remote-state-',dir=path.parent)\ntry:\n    with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output:\n        output.write(json.dumps(state,sort_keys=True,separators=(',',':'))+'\\n'); output.flush(); os.fsync(output.fileno())\n    os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,path)\nfinally:\n    if os.path.exists(temporary): os.unlink(temporary)\nprint(json.dumps({'ok':True,'generation':state['generation']},sort_keys=True))\n`;
}

export async function recordVerifiedRemoteState(
  config: RemoteSetupConfig,
  desired: DesiredRemoteState,
  boundarySha256: string,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<InstalledRemoteState> {
  const before = await readInstalledRemoteState(config, transport);
  const comparison = compareRemoteState(desired, before);
  if (!["NO_CHANGE", "APPLICATION_DECLARATION_ONLY"].includes(comparison.changeType)) {
    throw new OpsHavenError("POLICY_DENIED", "Remote setup postconditions do not match the desired canonical state.", false, {
      expectedMode: desired.dispatcherMode,
      observedMode: before.dispatcherMode ?? "unknown",
      changeType: comparison.changeType,
    });
  }
  const result = await transport.runPython(stateRecordScript(desired, boundarySha256), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Verified remote state could not be recorded.", true);
  const recorded = await readInstalledRemoteState(config, transport);
  const final = compareRemoteState(desired, recorded);
  if (!final.compatible) throw new OpsHavenError("POLICY_DENIED", "Recorded remote state failed post-install verification.", false, { changeType: final.changeType });
  return recorded;
}

export function compatibilityDetails(comparison: RemoteStateComparison): Record<string, unknown> {
  return {
    expectedDispatcherMode: comparison.desired.dispatcherMode,
    installedDispatcherMode: comparison.installed.dispatcherMode ?? "unknown",
    expectedCapabilityDigest: `sha256:${comparison.desired.capabilityIdentitySha256}`,
    installedCapabilityDigest: comparison.installed.capabilityIdentitySha256 ? `sha256:${comparison.installed.capabilityIdentitySha256}` : "unavailable",
    expectedPolicyIdentity: `sha256:${comparison.desired.policySha256}`,
    installedPolicyIdentity: comparison.installed.policySha256 ? `sha256:${comparison.installed.policySha256}` : "unavailable",
    expectedApplicationScope: comparison.desired.applicationScope,
    installedApplicationScope: comparison.installed.applicationScope,
    expectedSource: "local reviewed configuration and build artifacts",
    installedSource: comparison.installed.source,
    changeType: comparison.changeType,
    diagnosis: comparison.compatible ? "Installed deployment state matches the reviewed local state." : comparison.reasons.join("; "),
  };
}
