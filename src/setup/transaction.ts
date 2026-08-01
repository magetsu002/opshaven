import { randomBytes } from "node:crypto";
import { sha256 } from "../canonical.js";
import { OpsHavenError } from "../errors.js";
import type { RemoteSetupConfig } from "./remote.js";
import type { DesiredRemoteState, RemoteSetupChangeType } from "./state.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export const REMOTE_TRANSACTION_PATH = "/var/lib/opshaven/synchronization-transaction.json" as const;
export const REMOTE_TRANSACTION_ROOT = "/var/lib/opshaven/transactions" as const;
export const GENERATION_RECEIPT_SCHEMA_VERSION = 1 as const;

export type SynchronizationPhase =
  | "INSPECT"
  | "PLAN"
  | "STAGE"
  | "VERIFY_STAGED"
  | "RECORD_PREVIOUS"
  | "ACTIVATE"
  | "VERIFY_ACTIVE"
  | "COMMIT"
  | "CLEANUP"
  | "ROLLBACK_START"
  | "RESTORE_PREVIOUS"
  | "VERIFY_RESTORED"
  | "ROLLBACK_COMMIT"
  | "ROLLBACK_CLEANUP";

export interface CanonicalGenerationReceiptInput {
  readonly schemaVersion?: 1;
  readonly installationGeneration: number;
  readonly runtimeArtifactDigest: string;
  readonly dispatcherArtifactDigest: string;
  readonly policyDigest: string;
  readonly authorizationDigest: string;
  readonly applicationDeclarationDigest: string;
  readonly platform: string;
  readonly architecture: string;
  readonly sourceBuildIdentity: string;
  readonly createdAt: string;
  readonly previousGenerationIdentity: string | null;
}

export interface CanonicalGenerationReceipt extends CanonicalGenerationReceiptInput {
  readonly schemaVersion: 1;
  readonly identitySha256: string;
}

export interface RemoteSynchronizationTransaction {
  readonly version: 1;
  readonly transactionId: string;
  readonly phase: SynchronizationPhase;
  readonly changeType: RemoteSetupChangeType;
  readonly hostBindingSha256: string;
  readonly desiredGenerationIdentity: string;
  readonly previousGenerationIdentity: string | null;
  readonly previousGenerationAvailable: boolean;
  readonly snapshotRoot: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly integritySha256: string;
  readonly lastError?: string;
}

export interface RemoteTransactionRollbackReceipt {
  readonly ok: true;
  readonly transactionId: string;
  readonly phase: "ROLLBACK_COMMIT";
  readonly restoredGenerationIdentity: string | null;
  readonly restored: readonly string[];
  readonly removed: readonly string[];
}

const DIGEST = /^[a-f0-9]{64}$/;
const SOURCE = /^[a-f0-9]{40}$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3,6})?Z$/;

function generationBase(input: CanonicalGenerationReceiptInput): CanonicalGenerationReceiptInput & { readonly schemaVersion: 1 } {
  return Object.freeze({
    schemaVersion: GENERATION_RECEIPT_SCHEMA_VERSION,
    installationGeneration: input.installationGeneration,
    runtimeArtifactDigest: input.runtimeArtifactDigest,
    dispatcherArtifactDigest: input.dispatcherArtifactDigest,
    policyDigest: input.policyDigest,
    authorizationDigest: input.authorizationDigest,
    applicationDeclarationDigest: input.applicationDeclarationDigest,
    platform: input.platform,
    architecture: input.architecture,
    sourceBuildIdentity: input.sourceBuildIdentity,
    createdAt: input.createdAt,
    previousGenerationIdentity: input.previousGenerationIdentity,
  });
}

export function createCanonicalGenerationReceipt(input: CanonicalGenerationReceiptInput): CanonicalGenerationReceipt {
  const base = generationBase(input);
  if (!Number.isSafeInteger(base.installationGeneration) || base.installationGeneration < 1) throw new OpsHavenError("CONFIG_INVALID", "Installation generation is invalid.");
  for (const [name, value] of Object.entries({
    runtimeArtifactDigest: base.runtimeArtifactDigest,
    dispatcherArtifactDigest: base.dispatcherArtifactDigest,
    policyDigest: base.policyDigest,
    authorizationDigest: base.authorizationDigest,
    applicationDeclarationDigest: base.applicationDeclarationDigest,
  })) if (!DIGEST.test(value)) throw new OpsHavenError("CONFIG_INVALID", `Canonical receipt ${name} is invalid.`);
  if (!SOURCE.test(base.sourceBuildIdentity)) throw new OpsHavenError("CONFIG_INVALID", "Canonical receipt source build identity is invalid.");
  if (!ISO_TIME.test(base.createdAt)) throw new OpsHavenError("CONFIG_INVALID", "Canonical receipt creation time is invalid.");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(base.platform) || !/^[A-Za-z0-9._-]{1,64}$/.test(base.architecture)) throw new OpsHavenError("CONFIG_INVALID", "Canonical receipt platform identity is invalid.");
  if (base.previousGenerationIdentity !== null && !DIGEST.test(base.previousGenerationIdentity)) throw new OpsHavenError("CONFIG_INVALID", "Canonical receipt previous-generation binding is invalid.");
  return Object.freeze({ ...base, identitySha256: sha256(base) });
}

export function verifyCanonicalGenerationReceipt(value: CanonicalGenerationReceipt): CanonicalGenerationReceipt {
  const expected = createCanonicalGenerationReceipt(value);
  if (value.schemaVersion !== GENERATION_RECEIPT_SCHEMA_VERSION || value.identitySha256 !== expected.identitySha256) throw new OpsHavenError("POLICY_DENIED", "Canonical generation receipt integrity verification failed.");
  return value;
}

export function synchronizationHostBinding(config: RemoteSetupConfig): string {
  return sha256({
    host: config.target.host,
    port: config.target.port,
    administrator: config.target.adminUser,
    hostKey: config.target.expectedHostKeySha256,
    runtimeRoot: config.remote.runtimeRoot,
    stateDirectory: config.remote.stateDirectory,
  });
}

function managedPaths(config: RemoteSetupConfig): readonly string[] {
  return Object.freeze([
    config.remote.runtimeRoot,
    `${config.remote.stateDirectory}/runtime-manifest.json`,
    config.remote.configPath,
    config.remote.wrapperPath,
    `/home/${config.remote.account}/.ssh/authorized_keys`,
    "/etc/opshaven/approval-public.pem",
    `${config.remote.configPath}.capability.json`,
    `${config.remote.configPath}.declaration.json`,
    `${config.remote.configPath}.declaration-binding.json`,
    `${config.remote.configPath}.response-private.pem`,
    `${config.remote.configPath}.response-public.pem`,
    "/var/lib/opshaven/remote-state.json",
    config.remote.receiptPath,
  ]);
}

function parseTransaction(value: unknown): RemoteSynchronizationTransaction {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote synchronization transaction is malformed.");
  const record = value as Record<string, unknown>;
  const phases: readonly SynchronizationPhase[] = ["INSPECT", "PLAN", "STAGE", "VERIFY_STAGED", "RECORD_PREVIOUS", "ACTIVATE", "VERIFY_ACTIVE", "COMMIT", "CLEANUP", "ROLLBACK_START", "RESTORE_PREVIOUS", "VERIFY_RESTORED", "ROLLBACK_COMMIT", "ROLLBACK_CLEANUP"];
  if (record.version !== 1 || typeof record.transactionId !== "string" || !/^[a-f0-9]{32}$/.test(record.transactionId)
    || !phases.includes(record.phase as SynchronizationPhase) || typeof record.changeType !== "string"
    || typeof record.hostBindingSha256 !== "string" || !DIGEST.test(record.hostBindingSha256)
    || typeof record.desiredGenerationIdentity !== "string" || !DIGEST.test(record.desiredGenerationIdentity)
    || !(record.previousGenerationIdentity === null || typeof record.previousGenerationIdentity === "string" && DIGEST.test(record.previousGenerationIdentity))
    || typeof record.previousGenerationAvailable !== "boolean" || typeof record.snapshotRoot !== "string"
    || typeof record.createdAt !== "string" || typeof record.updatedAt !== "string"
    || typeof record.integritySha256 !== "string" || !DIGEST.test(record.integritySha256)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote synchronization transaction evidence is incomplete.");
  }
  return Object.freeze(record as unknown as RemoteSynchronizationTransaction);
}

function beginScript(config: RemoteSetupConfig, desired: DesiredRemoteState, changeType: RemoteSetupChangeType, transactionId: string): string {
  const request = JSON.stringify({
    version: 1,
    transactionId,
    changeType,
    transactionPath: REMOTE_TRANSACTION_PATH,
    transactionRoot: REMOTE_TRANSACTION_ROOT,
    hostBindingSha256: synchronizationHostBinding(config),
    desired,
    paths: managedPaths(config),
    runtimeRoot: config.remote.runtimeRoot,
    runtimeManifest: `${config.remote.stateDirectory}/runtime-manifest.json`,
    receiptPath: config.remote.receiptPath,
    statePath: "/var/lib/opshaven/remote-state.json",
    configPath: config.remote.configPath,
    capabilityPath: `${config.remote.configPath}.capability.json`,
    declarationPath: `${config.remote.configPath}.declaration.json`,
    dispatcherPath: `${config.remote.runtimeRoot}/src/remote/dispatcher.js`,
  });
  return `import hashlib,json,os,pathlib,platform,shutil,stat,tempfile,datetime\nR=json.loads(${JSON.stringify(request)})\ndef fail(message): raise RuntimeError(message)\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef digest_bytes(value): return hashlib.sha256(value).hexdigest()\ndef digest_file(path,maximum=33554432):\n info=os.lstat(path)\n if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size>maximum: fail('unsafe managed file')\n h=hashlib.sha256()\n with open(path,'rb') as handle:\n  while True:\n   chunk=handle.read(1048576)\n   if not chunk: break\n   h.update(chunk)\n return h.hexdigest()\ndef digest_tree(root):\n root=pathlib.Path(root)\n if root.is_symlink() or not root.is_dir(): fail('unsafe managed directory')\n files=[]\n for item in sorted(root.rglob('*')):\n  if item.is_symlink(): fail('managed directory contains a symbolic link')\n  if item.is_dir(): continue\n  if not item.is_file(): fail('managed directory contains an unsupported object')\n  files.append({'path':item.relative_to(root).as_posix(),'sha256':digest_file(item)})\n  if len(files)>4096: fail('managed directory contains too many files')\n return digest_bytes(canonical(files).encode('utf-8'))\ndef read_json(path):\n digest_file(path,2097152)\n with open(path,'r',encoding='utf-8') as handle: return json.load(handle)\ndef atomic_json(value,path):\n path=pathlib.Path(path); path.parent.mkdir(parents=True,exist_ok=True)\n descriptor,temporary=tempfile.mkstemp(prefix=f'.{path.name}.opshaven-',dir=path.parent)\n try:\n  with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output: output.write(canonical(value)+'\\n'); output.flush(); os.fsync(output.fileno())\n  os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,path)\n finally:\n  if os.path.exists(temporary): os.unlink(temporary)\ndef receipt_identity(receipt,state):\n manifest=read_json(R['runtimeManifest']); policy=read_json(R['configPath']); generation=state.get('generation')\n if not isinstance(generation,int) or generation<1: fail('previous generation is invalid')\n source=receipt.get('sourceSha')\n if not isinstance(source,str) or len(source)!=40 or any(ch not in '0123456789abcdef' for ch in source): fail('previous source build identity is invalid')\n base={'schemaVersion':1,'installationGeneration':generation,'runtimeArtifactDigest':manifest.get('treeSha256'),'dispatcherArtifactDigest':digest_file(R['dispatcherPath']),'policyDigest':digest_bytes(canonical(policy).encode('utf-8')),'authorizationDigest':digest_file(R['capabilityPath']),'applicationDeclarationDigest':digest_file(R['declarationPath']),'platform':platform.system(),'architecture':platform.machine(),'sourceBuildIdentity':source,'createdAt':state.get('recordedAt') or receipt.get('installedAt') or datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),'previousGenerationIdentity':state.get('previousGenerationIdentity')}\n for key in ('runtimeArtifactDigest','dispatcherArtifactDigest','policyDigest','authorizationDigest','applicationDeclarationDigest'):\n  if not isinstance(base.get(key),str) or len(base[key])!=64: fail(f'previous {key} is invalid')\n if base['previousGenerationIdentity'] is not None and (not isinstance(base['previousGenerationIdentity'],str) or len(base['previousGenerationIdentity'])!=64): fail('previous generation chain is invalid')\n base['identitySha256']=digest_bytes(canonical(base).encode('utf-8')); return base\ntransaction_path=pathlib.Path(R['transactionPath'])\nif transaction_path.exists():\n existing=read_json(transaction_path)\n if existing.get('phase') not in ('COMMIT','CLEANUP','ROLLBACK_COMMIT','ROLLBACK_CLEANUP'): fail('an unresolved synchronization transaction already exists')\ncreated=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')\nsnapshot_root=pathlib.Path(R['transactionRoot'])/R['transactionId']/ 'previous'\nif snapshot_root.exists(): fail('transaction snapshot already exists')\nsnapshot_root.mkdir(parents=True,mode=0o700); os.chmod(snapshot_root,0o700); os.chown(snapshot_root,0,0)\nreceipt_path=pathlib.Path(R['receiptPath']); state_path=pathlib.Path(R['statePath']); previous=None\nif receipt_path.exists() or state_path.exists():\n if not receipt_path.exists() or not state_path.exists(): fail('previous generation identity is partial')\n receipt=read_json(receipt_path); state=read_json(state_path); previous=receipt_identity(receipt,state)\nentries=[]\nfor raw in R['paths']:\n source=pathlib.Path(raw); relative=pathlib.Path(str(source).lstrip('/')); destination=snapshot_root/relative\n if not source.exists(): entries.append({'path':raw,'present':False,'kind':'absent','digest':None}); continue\n if source.is_symlink(): fail('managed path is a symbolic link')\n destination.parent.mkdir(parents=True,exist_ok=True)\n if source.is_dir(): shutil.copytree(source,destination,symlinks=False); kind='directory'; digest=digest_tree(source)\n elif source.is_file(): shutil.copy2(source,destination,follow_symlinks=False); kind='file'; digest=digest_file(source)\n else: fail('managed path has unsupported type')\n entries.append({'path':raw,'present':True,'kind':kind,'digest':digest})\nmanifest={'version':1,'entries':entries}; atomic_json(manifest,snapshot_root/'snapshot.json')\ndesired_base={'schemaVersion':1,'installationGeneration':(previous['installationGeneration']+1 if previous else 1),'runtimeArtifactDigest':R['desired']['runtimeSha256'],'dispatcherArtifactDigest':R['desired']['dispatcherSha256'],'policyDigest':R['desired']['policySha256'],'authorizationDigest':R['desired']['capabilityIdentitySha256'],'applicationDeclarationDigest':R['desired']['declarationSha256'],'platform':platform.system(),'architecture':platform.machine(),'sourceBuildIdentity':R['desired']['sourceSha'],'createdAt':created,'previousGenerationIdentity':previous['identitySha256'] if previous else None}\ndesired_identity=digest_bytes(canonical(desired_base).encode('utf-8'))\nrecord={'version':1,'transactionId':R['transactionId'],'phase':'RECORD_PREVIOUS','changeType':R['changeType'],'hostBindingSha256':R['hostBindingSha256'],'desiredGenerationIdentity':desired_identity,'previousGenerationIdentity':previous['identitySha256'] if previous else None,'previousGenerationAvailable':previous is not None,'snapshotRoot':str(snapshot_root),'createdAt':created,'updatedAt':created}\nrecord['integritySha256']=digest_bytes(canonical(record).encode('utf-8')); atomic_json(record,transaction_path)\nprint(canonical(record))\n`;
}

function phaseScript(config: RemoteSetupConfig, transactionId: string, phase: SynchronizationPhase, lastError?: string): string {
  const request = JSON.stringify({ path: REMOTE_TRANSACTION_PATH, transactionId, phase, hostBindingSha256: synchronizationHostBinding(config), lastError: lastError?.slice(0, 200) ?? null });
  return `import hashlib,json,os,pathlib,tempfile,datetime\nR=json.loads(${JSON.stringify(request)})\ndef fail(message): raise RuntimeError(message)\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef digest(value): return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()\ndef atomic(value,path):\n descriptor,temporary=tempfile.mkstemp(prefix=f'.{path.name}.opshaven-',dir=path.parent)\n try:\n  with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output: output.write(canonical(value)+'\\n'); output.flush(); os.fsync(output.fileno())\n  os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,path)\n finally:\n  if os.path.exists(temporary): os.unlink(temporary)\npath=pathlib.Path(R['path'])\nwith open(path,'r',encoding='utf-8') as handle: record=json.load(handle)\nintegrity=record.pop('integritySha256',None)\nif integrity!=digest(record): fail('transaction integrity mismatch')\nif record.get('transactionId')!=R['transactionId'] or record.get('hostBindingSha256')!=R['hostBindingSha256']: fail('transaction binding mismatch')\nrecord['phase']=R['phase']; record['updatedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')\nif R['lastError'] is not None: record['lastError']=R['lastError']\nrecord['integritySha256']=digest(record); atomic(record,path); print(canonical(record))\n`;
}

function rollbackScript(config: RemoteSetupConfig, transactionId: string): string {
  const request = JSON.stringify({ path: REMOTE_TRANSACTION_PATH, transactionId, hostBindingSha256: synchronizationHostBinding(config) });
  return `import hashlib,json,os,pathlib,shutil,stat,tempfile,datetime\nR=json.loads(${JSON.stringify(request)})\ndef fail(message): raise RuntimeError(message)\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef digest_value(value): return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()\ndef digest_file(path,maximum=33554432):\n info=os.lstat(path)\n if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size>maximum: fail('unsafe rollback file')\n h=hashlib.sha256()\n with open(path,'rb') as handle:\n  while True:\n   chunk=handle.read(1048576)\n   if not chunk: break\n   h.update(chunk)\n return h.hexdigest()\ndef digest_tree(root):\n root=pathlib.Path(root)\n if root.is_symlink() or not root.is_dir(): fail('unsafe rollback directory')\n files=[]\n for item in sorted(root.rglob('*')):\n  if item.is_symlink(): fail('rollback directory contains a symbolic link')\n  if item.is_dir(): continue\n  if not item.is_file(): fail('rollback directory contains an unsupported object')\n  files.append({'path':item.relative_to(root).as_posix(),'sha256':digest_file(item)})\n return hashlib.sha256(canonical(files).encode('utf-8')).hexdigest()\ndef atomic(value,path):\n descriptor,temporary=tempfile.mkstemp(prefix=f'.{path.name}.opshaven-',dir=path.parent)\n try:\n  with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output: output.write(canonical(value)+'\\n'); output.flush(); os.fsync(output.fileno())\n  os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,path)\n finally:\n  if os.path.exists(temporary): os.unlink(temporary)\ndef set_phase(record,phase):\n record['phase']=phase; record['updatedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'); record.pop('integritySha256',None); record['integritySha256']=digest_value(record); atomic(record,path)\npath=pathlib.Path(R['path'])\nwith open(path,'r',encoding='utf-8') as handle: record=json.load(handle)\nintegrity=record.pop('integritySha256',None)\nif integrity!=digest_value(record): fail('transaction integrity mismatch')\nif record.get('transactionId')!=R['transactionId'] or record.get('hostBindingSha256')!=R['hostBindingSha256']: fail('transaction binding mismatch')\nrecord['integritySha256']=integrity; set_phase(record,'ROLLBACK_START')\nsnapshot=pathlib.Path(record.get('snapshotRoot',''))\nif not snapshot.is_absolute() or snapshot.parent.name!='previous' and snapshot.name!='previous': fail('transaction snapshot path is invalid')\nmanifest_path=snapshot/'snapshot.json'; digest_file(manifest_path,2097152)\nwith open(manifest_path,'r',encoding='utf-8') as handle: manifest=json.load(handle)\nif manifest.get('version')!=1 or not isinstance(manifest.get('entries'),list): fail('transaction snapshot manifest is invalid')\nset_phase(record,'RESTORE_PREVIOUS'); restored=[]; removed=[]\nfor entry in manifest['entries']:\n raw=entry.get('path'); present=entry.get('present'); kind=entry.get('kind'); expected=entry.get('digest')\n if not isinstance(raw,str) or not raw.startswith('/') or not isinstance(present,bool): fail('snapshot entry is invalid')\n destination=pathlib.Path(raw); backup=snapshot/pathlib.Path(raw.lstrip('/'))\n if destination.is_symlink(): fail('refusing symlinked active rollback path')\n if destination.exists():\n  if destination.is_dir(): shutil.rmtree(destination)\n  elif destination.is_file(): destination.unlink()\n  else: fail('active rollback path has unsupported type')\n if not present: removed.append(raw); continue\n if backup.is_symlink() or not backup.exists(): fail('previous generation artifact is unavailable')\n destination.parent.mkdir(parents=True,exist_ok=True)\n if kind=='directory':\n  if digest_tree(backup)!=expected: fail('previous generation directory digest mismatch')\n  shutil.copytree(backup,destination,symlinks=False)\n elif kind=='file':\n  if digest_file(backup)!=expected: fail('previous generation file digest mismatch')\n  shutil.copy2(backup,destination,follow_symlinks=False)\n else: fail('snapshot entry kind is invalid')\n restored.append(raw)\nset_phase(record,'VERIFY_RESTORED')\nfor entry in manifest['entries']:\n raw=entry['path']; destination=pathlib.Path(raw)\n if not entry['present']:\n  if destination.exists(): fail('rollback removal verification failed')\n elif entry['kind']=='directory':\n  if digest_tree(destination)!=entry['digest']: fail('restored directory verification failed')\n elif digest_file(destination)!=entry['digest']: fail('restored file verification failed')\nset_phase(record,'ROLLBACK_COMMIT')\nprint(canonical({'ok':True,'transactionId':R['transactionId'],'phase':'ROLLBACK_COMMIT','restoredGenerationIdentity':record.get('previousGenerationIdentity'),'restored':restored,'removed':removed}))\n`;
}

export async function beginRemoteSynchronizationTransaction(
  config: RemoteSetupConfig,
  desired: DesiredRemoteState,
  changeType: RemoteSetupChangeType,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteSynchronizationTransaction> {
  const transactionId = randomBytes(16).toString("hex");
  const result = await transport.runPython(beginScript(config, desired, changeType, transactionId), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", `Remote transaction preparation failed safely: ${result.stderr.trim() || "no diagnostic"}.`, true);
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; } catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote transaction preparation returned invalid JSON."); }
  const record = parseTransaction(value);
  if (record.transactionId !== transactionId || record.hostBindingSha256 !== synchronizationHostBinding(config) || record.phase !== "RECORD_PREVIOUS") throw new OpsHavenError("POLICY_DENIED", "Remote transaction preparation evidence does not match the reviewed synchronization.");
  return record;
}

export async function advanceRemoteSynchronizationTransaction(
  config: RemoteSetupConfig,
  transactionId: string,
  phase: SynchronizationPhase,
  lastError?: string,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteSynchronizationTransaction> {
  const result = await transport.runPython(phaseScript(config, transactionId, phase, lastError), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", `Remote transaction phase ${phase} could not be recorded safely.`, true);
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; } catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote transaction phase response is invalid JSON."); }
  const record = parseTransaction(value);
  if (record.transactionId !== transactionId || record.phase !== phase) throw new OpsHavenError("POLICY_DENIED", "Remote transaction phase evidence is inconsistent.");
  return record;
}

export async function rollbackRemoteSynchronizationTransaction(
  config: RemoteSetupConfig,
  transactionId: string,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteTransactionRollbackReceipt> {
  const result = await transport.runPython(rollbackScript(config, transactionId), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", `Remote transaction rollback failed safely: ${result.stderr.trim() || "no diagnostic"}.`, true);
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; } catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote transaction rollback returned invalid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote transaction rollback evidence is malformed.");
  const record = value as Record<string, unknown>;
  if (record.ok !== true || record.transactionId !== transactionId || record.phase !== "ROLLBACK_COMMIT" || !Array.isArray(record.restored) || !Array.isArray(record.removed)
    || !(record.restoredGenerationIdentity === null || typeof record.restoredGenerationIdentity === "string" && DIGEST.test(record.restoredGenerationIdentity))) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote transaction rollback evidence is incomplete.");
  }
  return Object.freeze({ ok: true, transactionId, phase: "ROLLBACK_COMMIT", restoredGenerationIdentity: record.restoredGenerationIdentity as string | null, restored: Object.freeze(record.restored as string[]), removed: Object.freeze(record.removed as string[]) });
}
