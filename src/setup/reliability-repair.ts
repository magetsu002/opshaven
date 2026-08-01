import { randomBytes } from "node:crypto";
import { OpsHavenError } from "../errors.js";
import { inspectRemoteManagedFootprint } from "./footprint.js";
import { inspectInstallationHealth, type InstallationHealthReport } from "./health.js";
import {
  repairRemoteSetup as repairTransactionState,
  type CleanReinstallPreparationReceipt,
  type RemoteSetupRepairPlan,
  type RemoteSetupRepairReceipt,
} from "./repair.js";
import type { RemoteSetupConfig } from "./remote.js";
import { readInstalledRemoteState } from "./state.js";
import { REMOTE_TRANSACTION_PATH, REMOTE_TRANSACTION_ROOT, synchronizationHostBinding } from "./transaction.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

function actionFor(health: InstallationHealthReport): RemoteSetupRepairPlan["action"] {
  if (!health.repairRequired) return "none";
  if (health.repairClassification === "RESTORE_PREVIOUS_GENERATION") return "restore-previous";
  return "clean-reinstall-required";
}

function changesFor(health: InstallationHealthReport): readonly string[] {
  if (!health.repairRequired) {
    if (health.migrationStatus === "required") {
      return Object.freeze([
        "No recovery mutation is required.",
        "Run opshaven setup remote to perform the reviewed canonical schema migration.",
      ]);
    }
    return Object.freeze(["No damaged installation evidence or unresolved synchronization transaction requires repair."]);
  }
  if (health.repairClassification === "RESTORE_PREVIOUS_GENERATION") {
    return Object.freeze([
      "Validate the immutable previous-generation snapshot and receipt chain.",
      "Restore only the exact recorded previous runtime, dispatcher, authorization, declarations, and canonical state.",
      "Verify the restored boundary and append repair audit evidence.",
      "Preserve the failed transaction and generation evidence.",
    ]);
  }
  return Object.freeze([
    "Preserve current manifests, invalid receipts, transaction history, and audit evidence.",
    "Verify the bounded recovery-evidence manifest before changing active paths.",
    "Remove only fixed OpsHaven-managed active paths after evidence verification.",
    "Install one complete reviewed generation and create canonical receipts.",
    "Verify dispatcher, authorization, canonical readiness, and the restricted boundary.",
  ]);
}

function planFromHealth(health: InstallationHealthReport): RemoteSetupRepairPlan {
  const transaction = health.transaction.transaction;
  return Object.freeze({
    version: 1,
    action: actionFor(health),
    transactionId: transaction?.transactionId ?? null,
    lastCompletedPhase: health.transaction.lastCompletedPhase,
    desiredGeneration: transaction?.desiredGenerationIdentity ?? null,
    previousGeneration: transaction?.previousGenerationIdentity ?? null,
    rollbackAvailable: health.transaction.rollbackAvailable,
    evidencePreserved: true,
    changes: changesFor(health),
  });
}

export async function inspectRemoteSetupRepair(
  config: RemoteSetupConfig,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteSetupRepairPlan> {
  return planFromHealth(await inspectInstallationHealth(config, transport, false));
}

function managedActivePaths(config: RemoteSetupConfig): readonly string[] {
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

function evidencePreservingReinstallScript(config: RemoteSetupConfig, evidenceId: string): string {
  const request = JSON.stringify({
    evidenceId,
    evidenceParent: "/var/lib/opshaven/recovery-evidence",
    transactionPath: REMOTE_TRANSACTION_PATH,
    transactionRoot: REMOTE_TRANSACTION_ROOT,
    hostBindingSha256: synchronizationHostBinding(config),
    maximumFileBytes: 32 * 1024 * 1024,
    maximumTreeBytes: 256 * 1024 * 1024,
    maximumFiles: 4096,
    paths: managedActivePaths(config),
  });
  return `import hashlib,json,os,pathlib,shutil,stat,tempfile,datetime\nR=json.loads(${JSON.stringify(request)})\ndef fail(message): raise RuntimeError(message)\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef digest_file(path):\n info=os.lstat(path)\n if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size>R['maximumFileBytes']: fail('unsafe or oversized managed evidence file')\n h=hashlib.sha256()\n with open(path,'rb') as handle:\n  while True:\n   chunk=handle.read(1048576)\n   if not chunk: break\n   h.update(chunk)\n return h.hexdigest(),info.st_size\ndef digest_tree(root):\n root=pathlib.Path(root)\n if root.is_symlink() or not root.is_dir(): fail('unsafe managed evidence directory')\n files=[]; total=0\n for item in sorted(root.rglob('*')):\n  if item.is_symlink(): fail('managed evidence directory contains a symbolic link')\n  if item.is_dir(): continue\n  if not item.is_file(): fail('managed evidence directory contains an unsupported object')\n  digest,size=digest_file(item); total+=size\n  if total>R['maximumTreeBytes']: fail('managed evidence directory exceeds the reviewed size limit')\n  files.append({'path':item.relative_to(root).as_posix(),'sha256':digest,'size':size})\n  if len(files)>R['maximumFiles']: fail('managed evidence directory contains too many files')\n return hashlib.sha256(canonical(files).encode('utf-8')).hexdigest(),total,len(files)\ndef atomic_json(value,path):\n path.parent.mkdir(parents=True,exist_ok=True)\n descriptor,temporary=tempfile.mkstemp(prefix=f'.{path.name}.opshaven-',dir=path.parent)\n try:\n  with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output: output.write(canonical(value)+'\\n'); output.flush(); os.fsync(output.fileno())\n  os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,path)\n finally:\n  if os.path.exists(temporary): os.unlink(temporary)\nevidence_parent=pathlib.Path(R['evidenceParent'])\nif evidence_parent.exists():\n parent_info=os.lstat(evidence_parent)\n if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode): fail('recovery evidence parent is unsafe')\nelse:\n evidence_parent.mkdir(parents=True,mode=0o700); os.chmod(evidence_parent,0o700); os.chown(evidence_parent,0,0)\nevidence=evidence_parent/R['evidenceId']\nif evidence.exists(): fail('recovery evidence destination already exists')\nevidence.mkdir(mode=0o700); os.chmod(evidence,0o700); os.chown(evidence,0,0)\nentries=[]; preserved=[]; total_preserved=0\nfor raw in [*R['paths'],R['transactionPath']]:\n source=pathlib.Path(raw); destination=evidence/'active'/pathlib.Path(raw.lstrip('/'))\n if not source.exists(): entries.append({'path':raw,'present':False,'kind':'absent','digest':None,'bytes':0,'files':0}); continue\n if source.is_symlink(): fail('managed active path is a symbolic link')\n destination.parent.mkdir(parents=True,exist_ok=True)\n if source.is_dir():\n  digest,size,count=digest_tree(source); total_preserved+=size\n  if total_preserved>R['maximumTreeBytes']: fail('total recovery evidence exceeds the reviewed size limit')\n  shutil.copytree(source,destination,symlinks=False); kind='directory'\n elif source.is_file():\n  digest,size=digest_file(source); count=1; total_preserved+=size\n  if total_preserved>R['maximumTreeBytes']: fail('total recovery evidence exceeds the reviewed size limit')\n  shutil.copy2(source,destination,follow_symlinks=False); kind='file'\n else: fail('managed active path has unsupported type')\n entries.append({'path':raw,'present':True,'kind':kind,'digest':digest,'bytes':size,'files':count}); preserved.append(raw)\ntransaction_id=None; transaction_path=pathlib.Path(R['transactionPath'])\nif transaction_path.exists():\n try:\n  with open(transaction_path,'r',encoding='utf-8') as handle: transaction=json.load(handle)\n  transaction_id=transaction.get('transactionId') if isinstance(transaction.get('transactionId'),str) else None\n  if transaction_id and len(transaction_id)==32:\n   history=pathlib.Path(R['transactionRoot'])/transaction_id\n   if history.exists():\n    if history.is_symlink() or not history.is_dir(): fail('transaction history is unsafe')\n    digest,size,count=digest_tree(history); total_preserved+=size\n    if total_preserved>R['maximumTreeBytes']: fail('total recovery evidence exceeds the reviewed size limit')\n    destination=evidence/'transaction-history'; shutil.copytree(history,destination,symlinks=False)\n    entries.append({'path':str(history),'present':True,'kind':'directory','digest':digest,'bytes':size,'files':count})\n except (OSError,ValueError,AttributeError): pass\nmanifest={'version':1,'evidenceId':R['evidenceId'],'hostBindingSha256':R['hostBindingSha256'],'transactionId':transaction_id,'createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),'totalBytes':total_preserved,'entries':entries}\nmanifest_sha=hashlib.sha256(canonical(manifest).encode('utf-8')).hexdigest(); manifest['manifestSha256']=manifest_sha; atomic_json(manifest,evidence/'evidence-manifest.json')\nwith open(evidence/'evidence-manifest.json','r',encoding='utf-8') as handle: verified=json.load(handle)\nrecorded=verified.pop('manifestSha256',None)\nif recorded!=hashlib.sha256(canonical(verified).encode('utf-8')).hexdigest(): fail('recovery evidence manifest verification failed')\nremoved=[]\nfor raw in R['paths']:\n target=pathlib.Path(raw)\n if not target.exists(): continue\n if target.is_symlink(): fail('refusing symlinked active path during clean reinstall preparation')\n if target.is_dir(): shutil.rmtree(target)\n elif target.is_file(): target.unlink()\n else: fail('active path has unsupported type')\n removed.append(raw)\nif transaction_path.exists():\n if transaction_path.is_symlink() or not transaction_path.is_file(): fail('transaction path became unsafe')\n transaction_path.unlink(); removed.append(R['transactionPath'])\nprint(canonical({'ok':True,'action':'clean-reinstall-prepared','evidenceId':R['evidenceId'],'evidenceRoot':str(evidence),'evidenceManifestSha256':manifest_sha,'preserved':preserved,'removed':removed,'transactionId':transaction_id,'preparedAt':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')}))\n`;
}

function parsePreparation(stdout: string, evidenceId: string): CleanReinstallPreparationReceipt {
  let value: unknown;
  try { value = JSON.parse(stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Clean reinstall preparation returned invalid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Clean reinstall preparation evidence is malformed.");
  const record = value as Record<string, unknown>;
  if (record.ok !== true || record.action !== "clean-reinstall-prepared" || record.evidenceId !== evidenceId
    || typeof record.evidenceRoot !== "string" || !record.evidenceRoot.startsWith("/var/lib/opshaven/recovery-evidence/")
    || typeof record.evidenceManifestSha256 !== "string" || !/^[a-f0-9]{64}$/.test(record.evidenceManifestSha256)
    || !Array.isArray(record.preserved) || !Array.isArray(record.removed) || typeof record.preparedAt !== "string"
    || !(record.transactionId === null || typeof record.transactionId === "string" && /^[a-f0-9]{32}$/.test(record.transactionId))) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Clean reinstall preparation evidence is incomplete.");
  }
  const paths = (items: unknown[]): readonly string[] => Object.freeze(items.map((item) => {
    if (typeof item !== "string" || !item.startsWith("/") || item.length > 4096) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Clean reinstall path evidence is invalid.");
    return item;
  }));
  return Object.freeze({
    ok: true,
    action: "clean-reinstall-prepared",
    evidenceId,
    evidenceRoot: record.evidenceRoot,
    evidenceManifestSha256: record.evidenceManifestSha256,
    preserved: paths(record.preserved),
    removed: paths(record.removed),
    transactionId: record.transactionId as string | null,
    preparedAt: record.preparedAt,
  });
}

export async function prepareReviewedCleanReinstall(
  config: RemoteSetupConfig,
  approved: boolean,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<CleanReinstallPreparationReceipt> {
  if (!approved) throw new OpsHavenError("POLICY_DENIED", "Reviewed clean reinstall preparation requires explicit approval.");
  const health = await inspectInstallationHealth(config, transport, false);
  const plan = planFromHealth(health);
  if (plan.action !== "clean-reinstall-required") throw new OpsHavenError("POLICY_DENIED", "A reviewed clean reinstall is not the selected recovery action.", false, { repairPlan: plan });
  if (health.repairClassification === "MANUAL_RECOVERY_REQUIRED") throw new OpsHavenError("POLICY_DENIED", "The remote installation state is unknown or unsafe and requires manual reviewed recovery.", false, { repairPlan: plan });
  const evidenceId = randomBytes(16).toString("hex");
  const result = await transport.runPython(evidencePreservingReinstallScript(config, evidenceId), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Failed-state evidence could not be preserved safely. No clean reinstall was started.", true, { failedStage: "preserve recovery evidence" });
  const receipt = parsePreparation(result.stdout, evidenceId);
  const [after, footprint] = await Promise.all([
    readInstalledRemoteState(config, transport),
    inspectRemoteManagedFootprint(config, transport),
  ]);
  if (after.status !== "absent" || footprint.kind !== "empty") throw new OpsHavenError("POLICY_DENIED", "Clean reinstall preparation did not reach an empty active installation state.", false, { evidenceRoot: receipt.evidenceRoot });
  return receipt;
}

export async function repairRemoteSetup(
  config: RemoteSetupConfig,
  approved: boolean,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteSetupRepairReceipt> {
  const health = await inspectInstallationHealth(config, transport, false);
  const plan = planFromHealth(health);
  if (plan.action === "restore-previous" || plan.action === "none") {
    return await repairTransactionState(config, approved, transport);
  }
  throw new OpsHavenError(
    "POLICY_DENIED",
    "The installation requires an evidence-preserving clean reinstall before synchronization can continue.",
    false,
    { repairPlan: plan, health, safeNextCommand: "opshaven setup repair --clean-reinstall --approve" },
  );
}
