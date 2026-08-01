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

export const REMOTE_STATE_SCHEMA_VERSION = 3 as const;
export const SETUP_DISPATCHER_MODE = "controlled" as const;
export const REMOTE_STATE_PATH = "/var/lib/opshaven/remote-state.json" as const;
export const MINIMUM_REMOTE_NODE_MAJOR = 22 as const;

export type RemoteSetupChangeType =
  | "NO_CHANGE"
  | "AUTHORIZATION_ONLY"
  | "APPLICATION_DECLARATION_ONLY"
  | "AUTHORIZATION_AND_DECLARATION"
  | "RUNTIME_UPDATE"
  | "DISPATCHER_UPDATE"
  | "FULL_INSTALL"
  | "REPAIR_REQUIRED";

export interface DesiredRemoteState {
  readonly schemaVersion: 3;
  readonly sourceSha: string;
  readonly dispatcherMode: "controlled";
  readonly runtimeSha256: string;
  readonly dispatcherSha256: string;
  readonly policyVersion: string;
  readonly policySha256: string;
  readonly capabilityIdentitySha256: string;
  readonly declarationSha256: string;
  readonly operatorVerificationIdentity: string;
  readonly applicationScope: readonly string[];
  readonly applicationScopeSha256: string;
  readonly minimumNodeMajor: 22;
}

export interface InstalledRemoteState {
  readonly status: "absent" | "complete" | "inconsistent";
  readonly source: "installed remote state";
  readonly schemaVersion: number | null;
  readonly generation: number | null;
  readonly recordedIdentityMatches: boolean | null;
  readonly sourceSha: string | null;
  readonly dispatcherMode: "controlled" | "read-only" | null;
  readonly runtimeSha256: string | null;
  readonly dispatcherSha256: string | null;
  readonly policyVersion: string | null;
  readonly policySha256: string | null;
  readonly capabilityIdentitySha256: string | null;
  readonly capabilityArtifactSha256: string | null;
  readonly declarationSha256: string | null;
  readonly operatorVerificationIdentity: string | null;
  readonly applicationScope: readonly string[];
  readonly applicationScopeSha256: string | null;
  readonly platform: string | null;
  readonly architecture: string | null;
  readonly nodeVersion: string | null;
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
function stableCapabilityIdentity(payload: ReturnType<typeof buildCapabilityPayload>): string {
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
  const identityPayload = buildCapabilityPayload(remoteConfig, SETUP_DISPATCHER_MODE, dispatcherSha256, "2100-01-01T00:00:00.000Z", "2000-01-01T00:00:00.000Z");
  const applicationScope = [...remoteConfig.resources.values()].filter((resource) => resource.kind === "application").map((resource) => resource.id).sort();
  return Object.freeze({
    schemaVersion: REMOTE_STATE_SCHEMA_VERSION,
    sourceSha: config.expectedSourceSha,
    dispatcherMode: SETUP_DISPATCHER_MODE,
    runtimeSha256: runtime.treeSha256,
    dispatcherSha256,
    policyVersion: remoteConfig.policyVersion,
    policySha256: sha256(policyDocument),
    capabilityIdentitySha256: stableCapabilityIdentity(identityPayload),
    declarationSha256: capabilityDeclarationHash(declaration),
    operatorVerificationIdentity: digestBytes(operatorPublic),
    applicationScope: Object.freeze(applicationScope),
    applicationScopeSha256: sha256(applicationScope),
    minimumNodeMajor: MINIMUM_REMOTE_NODE_MAJOR,
  });
}

function stateInspectionScript(config: RemoteSetupConfig): string {
  const paths = JSON.stringify({ receipt: config.remote.receiptPath, state: REMOTE_STATE_PATH, runtimeManifest: `${config.remote.stateDirectory}/runtime-manifest.json`, runtimeRoot: config.remote.runtimeRoot, config: config.remote.configPath, capability: `${config.remote.configPath}.capability.json`, declaration: `${config.remote.configPath}.declaration.json`, publicKey: "/etc/opshaven/approval-public.pem", nodeCandidates: config.remote.nodeCandidates });
  return `import base64,hashlib,json,os,pathlib,platform,stat,subprocess\nP=json.loads(${JSON.stringify(paths)})\ndef regular(path,maximum=16777216):\n p=pathlib.Path(path)\n try: info=os.lstat(p)\n except OSError: return False\n return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_size<=maximum\ndef read_json(path):\n if not regular(path,2097152): raise RuntimeError('missing or unsafe state artifact')\n with open(path,'r',encoding='utf-8') as handle: return json.load(handle)\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef digest_json(value): return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()\ndef digest_file(path):\n if not regular(path): raise RuntimeError('missing or unsafe state artifact')\n h=hashlib.sha256()\n with open(path,'rb') as handle:\n  while True:\n   chunk=handle.read(1048576)\n   if not chunk: break\n   h.update(chunk)\n return h.hexdigest()\ndef node_version():\n for raw in P['nodeCandidates']:\n  candidate=pathlib.Path(raw)\n  if not regular(candidate,134217728) or not os.access(candidate,os.X_OK) or os.path.realpath(candidate)!=str(candidate): continue\n  result=subprocess.run([str(candidate),'--version'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10,check=False)\n  value=result.stdout.strip()\n  if result.returncode==0 and value.startswith('v') and value[1:].split('.')[0].isdigit(): return value\n return None\ndef absent():\n print(canonical({'status':'absent','source':'installed remote state'})); raise SystemExit(0)\nif not regular(P['receipt'],2097152): absent()\ntry:\n receipt=read_json(P['receipt'])\n rollback=receipt.get('rollback') if isinstance(receipt.get('rollback'),dict) else {}\n controlled=f"{P['runtimeRoot']}/src/remote/dispatcher.js"\n readonly=f"{P['runtimeRoot']}/src/remote/read-only-dispatcher.js"\n managed=[P['runtimeManifest'],P['config'],P['capability'],P['declaration'],P['publicKey'],controlled,readonly]\n if receipt.get('certified') is False and rollback.get('completed') is True and not any(regular(item,2097152) for item in managed): absent()\n capability_document=read_json(P['capability'])\n encoded=capability_document.get('payload','')\n if not isinstance(encoded,str): raise RuntimeError('capability payload is missing')\n padding='='*((4-len(encoded)%4)%4)\n capability=json.loads(base64.urlsafe_b64decode((encoded+padding).encode('ascii')).decode('utf-8'))\n stable={key:value for key,value in capability.items() if key not in ('issuedAt','expiresAt')}\n policy=read_json(P['config']); declaration=read_json(P['declaration']); manifest=read_json(P['runtimeManifest'])\n dispatcher=controlled if regular(controlled) else readonly if regular(readonly) else None\n if dispatcher is None: raise RuntimeError('installed dispatcher is missing')\n applications=sorted([item.get('id') for item in policy.get('resources',[]) if isinstance(item,dict) and item.get('kind')=='application' and isinstance(item.get('id'),str)])\n recorded=read_json(P['state']) if regular(P['state'],2097152) else {}\n recorded_schema=recorded.get('schemaVersion',1)\n actual={'status':'complete','source':'installed remote state','schemaVersion':recorded_schema,'generation':recorded.get('generation'),'recordedIdentityMatches':True,'sourceSha':receipt.get('sourceSha'),'dispatcherMode':capability.get('mode'),'runtimeSha256':manifest.get('treeSha256') or receipt.get('runtimeTreeSha256'),'dispatcherSha256':digest_file(dispatcher),'policyVersion':policy.get('policyVersion'),'policySha256':digest_json(policy),'capabilityIdentitySha256':digest_json(stable),'capabilityArtifactSha256':digest_file(P['capability']),'declarationSha256':digest_json(declaration),'operatorVerificationIdentity':digest_file(P['publicKey']),'applicationScope':applications,'applicationScopeSha256':digest_json(applications),'platform':platform.system(),'architecture':platform.machine(),'nodeVersion':node_version()}\n if recorded:\n  keys=['sourceSha','dispatcherMode','runtimeSha256','dispatcherSha256','policySha256','capabilityIdentitySha256','declarationSha256','operatorVerificationIdentity','applicationScopeSha256']\n  if isinstance(recorded_schema,int) and recorded_schema>=3: keys.extend(['policyVersion','platform','architecture','nodeVersion'])\n  mismatch=next((key for key in keys if recorded.get(key)!=actual.get(key)),None)\n  if mismatch: actual['recordedIdentityMatches']=False; actual['detail']=f'recorded remote state differs from installed {mismatch}'\n print(canonical(actual))\nexcept Exception as error:\n print(canonical({'status':'inconsistent','source':'installed remote state','schemaVersion':None,'generation':None,'recordedIdentityMatches':False,'sourceSha':None,'dispatcherMode':None,'runtimeSha256':None,'dispatcherSha256':None,'policyVersion':None,'policySha256':None,'capabilityIdentitySha256':None,'capabilityArtifactSha256':None,'declarationSha256':None,'operatorVerificationIdentity':None,'applicationScope':[],'applicationScopeSha256':None,'platform':platform.system(),'architecture':platform.machine(),'nodeVersion':None,'detail':str(error)[:200]}))\n`;
}
function optionalString(value: unknown, pattern: RegExp): string | null { return typeof value === "string" && pattern.test(value) ? value : null; }
function absentState(): InstalledRemoteState {
  return Object.freeze({ status: "absent", source: "installed remote state", schemaVersion: null, generation: null, recordedIdentityMatches: null, sourceSha: null, dispatcherMode: null, runtimeSha256: null, dispatcherSha256: null, policyVersion: null, policySha256: null, capabilityIdentitySha256: null, capabilityArtifactSha256: null, declarationSha256: null, operatorVerificationIdentity: null, applicationScope: Object.freeze([]), applicationScopeSha256: null, platform: null, architecture: null, nodeVersion: null });
}
export async function readInstalledRemoteState(config: RemoteSetupConfig, transport: RemoteAdminTransport = new PinnedSshAdminTransport(config)): Promise<InstalledRemoteState> {
  const result = await transport.runPython(stateInspectionScript(config), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Installed remote state could not be inspected safely.", true);
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; } catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Installed remote state response is not valid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Installed remote state response is malformed.");
  const record = value as Record<string, unknown>;
  if (record.status === "absent") return absentState();
  if (record.status !== "complete" && record.status !== "inconsistent") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Installed remote state status is invalid.");
  const applicationScope = Array.isArray(record.applicationScope) ? record.applicationScope.filter((item): item is string => typeof item === "string" && /^[a-z][a-z0-9._-]{0,63}$/.test(item)).sort() : [];
  return Object.freeze({
    status: record.status,
    source: "installed remote state",
    schemaVersion: Number.isInteger(record.schemaVersion) ? record.schemaVersion as number : null,
    generation: Number.isInteger(record.generation) ? record.generation as number : null,
    recordedIdentityMatches: typeof record.recordedIdentityMatches === "boolean" ? record.recordedIdentityMatches : null,
    sourceSha: optionalString(record.sourceSha, /^[a-f0-9]{40}$/),
    dispatcherMode: record.dispatcherMode === "controlled" || record.dispatcherMode === "read-only" ? record.dispatcherMode : null,
    runtimeSha256: optionalString(record.runtimeSha256, /^[a-f0-9]{64}$/),
    dispatcherSha256: optionalString(record.dispatcherSha256, /^[a-f0-9]{64}$/),
    policyVersion: optionalString(record.policyVersion, /^[A-Za-z0-9._-]{1,64}$/),
    policySha256: optionalString(record.policySha256, /^[a-f0-9]{64}$/),
    capabilityIdentitySha256: optionalString(record.capabilityIdentitySha256, /^[a-f0-9]{64}$/),
    capabilityArtifactSha256: optionalString(record.capabilityArtifactSha256, /^[a-f0-9]{64}$/),
    declarationSha256: optionalString(record.declarationSha256, /^[a-f0-9]{64}$/),
    operatorVerificationIdentity: optionalString(record.operatorVerificationIdentity, /^[a-f0-9]{64}$/),
    applicationScope: Object.freeze(applicationScope),
    applicationScopeSha256: optionalString(record.applicationScopeSha256, /^[a-f0-9]{64}$/),
    platform: optionalString(record.platform, /^[A-Za-z0-9._-]{1,64}$/),
    architecture: optionalString(record.architecture, /^[A-Za-z0-9._-]{1,64}$/),
    nodeVersion: optionalString(record.nodeVersion, /^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/),
    ...(typeof record.detail === "string" ? { detail: record.detail.slice(0, 200) } : {}),
  });
}
function repair(desired: DesiredRemoteState, installed: InstalledRemoteState, reasons: string[]): RemoteStateComparison { return Object.freeze({ desired, installed, changeType: "REPAIR_REQUIRED", reasons: Object.freeze(reasons), compatible: false }); }
function nodeMajor(version: string | null): number | null { const matched = version?.match(/^v([0-9]+)\./); return matched ? Number(matched[1]) : null; }
export function compareRemoteState(desired: DesiredRemoteState, installed: InstalledRemoteState): RemoteStateComparison {
  if (installed.status === "absent") return Object.freeze({ desired, installed, changeType: "FULL_INSTALL", reasons: Object.freeze(["no installed runtime state was found"]), compatible: false });
  if (installed.status === "inconsistent") return repair(desired, installed, [installed.detail ?? "installed state is incomplete or inconsistent"]);
  if (installed.schemaVersion === null || installed.schemaVersion > desired.schemaVersion) return repair(desired, installed, ["installed setup schema is missing or newer than this reviewed operator"]);
  if (installed.platform !== "Linux") return repair(desired, installed, [`remote platform is ${installed.platform ?? "unknown"}, expected Linux`]);
  if (!installed.architecture || !["x86_64", "aarch64", "arm64"].includes(installed.architecture)) return repair(desired, installed, [`remote architecture ${installed.architecture ?? "unknown"} is unsupported`]);
  const major = nodeMajor(installed.nodeVersion);
  if (major === null || major < desired.minimumNodeMajor) return repair(desired, installed, [`remote Node.js ${installed.nodeVersion ?? "unknown"} is incompatible; version ${desired.minimumNodeMajor} or newer is required`]);
  const reasons: string[] = [];
  const dispatcherChanged = installed.dispatcherMode !== desired.dispatcherMode || installed.dispatcherSha256 !== desired.dispatcherSha256;
  const runtimeChanged = installed.sourceSha !== desired.sourceSha || installed.runtimeSha256 !== desired.runtimeSha256;
  if (installed.dispatcherMode !== desired.dispatcherMode) reasons.push(`dispatcher mode is ${installed.dispatcherMode ?? "unknown"}, expected ${desired.dispatcherMode}`);
  if (installed.dispatcherSha256 !== desired.dispatcherSha256) reasons.push("dispatcher artifact identity differs");
  if (installed.sourceSha !== desired.sourceSha) reasons.push("runtime source version differs");
  if (installed.runtimeSha256 !== desired.runtimeSha256) reasons.push("runtime artifact identity differs");
  if (dispatcherChanged) return Object.freeze({ desired, installed, changeType: "DISPATCHER_UPDATE", reasons: Object.freeze(reasons), compatible: false });
  if (runtimeChanged) return Object.freeze({ desired, installed, changeType: "RUNTIME_UPDATE", reasons: Object.freeze(reasons), compatible: false });
  const authorizationDiffers = installed.policyVersion !== desired.policyVersion || installed.policySha256 !== desired.policySha256 || installed.capabilityIdentitySha256 !== desired.capabilityIdentitySha256 || installed.operatorVerificationIdentity !== desired.operatorVerificationIdentity || installed.applicationScopeSha256 !== desired.applicationScopeSha256;
  const declarationDiffers = installed.declarationSha256 !== desired.declarationSha256 || installed.schemaVersion < desired.schemaVersion || installed.recordedIdentityMatches === false;
  if (authorizationDiffers) reasons.push("signed authorization, policy, operator identity, or application scope differs");
  if (installed.declarationSha256 !== desired.declarationSha256) reasons.push("reviewed application declaration differs");
  if (installed.schemaVersion < desired.schemaVersion) reasons.push("legacy installed state requires explicit schema synchronization");
  if (installed.recordedIdentityMatches === false) reasons.push(installed.detail ?? "canonical state record differs from complete installed artifacts");
  let changeType: RemoteSetupChangeType = "NO_CHANGE";
  if (authorizationDiffers && declarationDiffers) changeType = "AUTHORIZATION_AND_DECLARATION";
  else if (authorizationDiffers) changeType = "AUTHORIZATION_ONLY";
  else if (declarationDiffers) changeType = "APPLICATION_DECLARATION_ONLY";
  return Object.freeze({ desired, installed, changeType, reasons: Object.freeze(reasons), compatible: changeType === "NO_CHANGE" });
}
export async function prepareRemoteState(config: RemoteSetupConfig, transport: RemoteAdminTransport = new PinnedSshAdminTransport(config)): Promise<RemoteStateComparison> {
  const [desired, installed] = await Promise.all([buildDesiredRemoteState(config), readInstalledRemoteState(config, transport)]);
  return compareRemoteState(desired, installed);
}
function stateRecordScript(config: RemoteSetupConfig, desired: DesiredRemoteState, boundarySha256: string): string {
  const request = JSON.stringify({ path: REMOTE_STATE_PATH, desired, boundarySha256, nodeCandidates: config.remote.nodeCandidates });
  return `import json,os,pathlib,platform,subprocess,tempfile,datetime\nrequest=json.loads(${JSON.stringify(request)})\npath=pathlib.Path(request['path']); previous={}\ntry:\n with open(path,'r',encoding='utf-8') as handle: previous=json.load(handle)\nexcept (OSError,ValueError): pass\ndef node_version():\n for raw in request['nodeCandidates']:\n  candidate=pathlib.Path(raw)\n  if candidate.is_file() and not candidate.is_symlink() and os.access(candidate,os.X_OK) and os.path.realpath(candidate)==str(candidate):\n   result=subprocess.run([str(candidate),'--version'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10,check=False); value=result.stdout.strip()\n   if result.returncode==0 and value.startswith('v') and value[1:].split('.')[0].isdigit(): return value\n raise RuntimeError('compatible Node.js executable is unavailable')\nstate=dict(request['desired']); state['platform']=platform.system(); state['architecture']=platform.machine(); state['nodeVersion']=node_version(); state['boundarySha256']=request['boundarySha256']; state['recordedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')\nidentity_keys=list(request['desired'].keys())+['platform','architecture','nodeVersion']; unchanged=all(previous.get(key)==state.get(key) for key in identity_keys); previous_generation=int(previous.get('generation',0)) if isinstance(previous.get('generation',0),int) else 0; state['generation']=previous_generation if unchanged and previous_generation>0 else previous_generation+1\npath.parent.mkdir(parents=True,exist_ok=True); descriptor,temporary=tempfile.mkstemp(prefix='.remote-state-',dir=path.parent)\ntry:\n with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output: output.write(json.dumps(state,sort_keys=True,separators=(',',':'))+'\\n'); output.flush(); os.fsync(output.fileno())\n os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,path)\nfinally:\n if os.path.exists(temporary): os.unlink(temporary)\nprint(json.dumps({'ok':True,'generation':state['generation']},sort_keys=True))\n`;
}
export async function recordVerifiedRemoteState(config: RemoteSetupConfig, desired: DesiredRemoteState, boundarySha256: string, transport: RemoteAdminTransport = new PinnedSshAdminTransport(config)): Promise<InstalledRemoteState> {
  const before = await readInstalledRemoteState(config, transport); const comparison = compareRemoteState(desired, before);
  if (comparison.changeType !== "NO_CHANGE") throw new OpsHavenError("POLICY_DENIED", "Remote setup postconditions do not match the desired canonical state.", false, { expectedMode: desired.dispatcherMode, observedMode: before.dispatcherMode ?? "unknown", changeType: comparison.changeType });
  const result = await transport.runPython(stateRecordScript(config, desired, boundarySha256), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Verified remote state could not be recorded.", true);
  const recorded = await readInstalledRemoteState(config, transport); const final = compareRemoteState(desired, recorded);
  if (!final.compatible) throw new OpsHavenError("POLICY_DENIED", "Recorded remote state failed post-install verification.", false, { changeType: final.changeType });
  return recorded;
}
function digest(value: string | null): string { return value ? `sha256:${value}` : "unavailable"; }
export function compatibilityDetails(comparison: RemoteStateComparison): Record<string, unknown> {
  const installedMode = comparison.installed.dispatcherMode === "read-only" ? "legacy-read-only" : comparison.installed.dispatcherMode ?? "unknown";
  return {
    expectedRuntimeVersion: comparison.desired.sourceSha, installedRuntimeVersion: comparison.installed.sourceSha ?? "unavailable",
    expectedRuntimeDigest: digest(comparison.desired.runtimeSha256), installedRuntimeDigest: digest(comparison.installed.runtimeSha256),
    expectedDispatcher: "controlled / capability-scoped", installedDispatcher: installedMode === "controlled" ? "controlled / capability-scoped" : installedMode,
    expectedDispatcherMode: comparison.desired.dispatcherMode, installedDispatcherMode: installedMode,
    expectedDispatcherDigest: digest(comparison.desired.dispatcherSha256), installedDispatcherDigest: digest(comparison.installed.dispatcherSha256),
    expectedPolicyVersion: comparison.desired.policyVersion, installedPolicyVersion: comparison.installed.policyVersion ?? "unavailable",
    expectedPolicyIdentity: digest(comparison.desired.policySha256), installedPolicyIdentity: digest(comparison.installed.policySha256),
    expectedCapabilityDigest: digest(comparison.desired.capabilityIdentitySha256), installedCapabilityDigest: digest(comparison.installed.capabilityIdentitySha256),
    expectedDeclarationDigest: digest(comparison.desired.declarationSha256), installedDeclarationDigest: digest(comparison.installed.declarationSha256),
    expectedApplicationScope: comparison.desired.applicationScope, installedApplicationScope: comparison.installed.applicationScope,
    installedPlatform: comparison.installed.platform ?? "unavailable", installedArchitecture: comparison.installed.architecture ?? "unavailable", installedNodeVersion: comparison.installed.nodeVersion ?? "unavailable",
    installationGeneration: comparison.installed.generation, recordedIdentityMatches: comparison.installed.recordedIdentityMatches,
    expectedSource: "local reviewed configuration and build artifacts", installedSource: comparison.installed.source,
    changeType: comparison.changeType, result: comparison.compatible ? "compatible" : "synchronization required",
    diagnosis: comparison.compatible ? "Installed deployment state matches the reviewed local state." : comparison.reasons.join("; "), repair: comparison.compatible ? null : "opshaven setup remote",
  };
}
