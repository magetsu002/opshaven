import { randomBytes } from "node:crypto";
import { AuditLog } from "../audit.js";
import { sha256 } from "../canonical.js";
import { loadConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { certifyRemoteBoundary, type RemoteBoundaryReceipt } from "./certify.js";
import type { RemoteSetupConfig } from "./remote.js";
import { rollbackRecordedSynchronization } from "./rollback.js";
import { readInstalledRemoteState, type InstalledRemoteState } from "./state.js";
import { inspectRemoteSynchronizationTransaction, type SynchronizationTransactionInspection } from "./transaction-inspection.js";
import { advanceRemoteSynchronizationTransaction, REMOTE_TRANSACTION_PATH, REMOTE_TRANSACTION_ROOT, synchronizationHostBinding } from "./transaction.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export interface RemoteSetupRepairPlan {
  readonly version: 1;
  readonly action: "restore-previous" | "none" | "clean-reinstall-required";
  readonly transactionId: string | null;
  readonly lastCompletedPhase: string | null;
  readonly desiredGeneration: string | null;
  readonly previousGeneration: string | null;
  readonly rollbackAvailable: boolean;
  readonly evidencePreserved: true;
  readonly changes: readonly string[];
}

export interface RemoteSetupRepairReceipt {
  readonly ok: true;
  readonly action: "restore-previous" | "none";
  readonly transactionId: string | null;
  readonly restoredGenerationIdentity: string | null;
  readonly installedGeneration: number | null;
  readonly boundary: RemoteBoundaryReceipt | null;
  readonly auditEvidenceDigest: string;
  readonly repairedAt: string;
}

export interface CleanReinstallPreparationReceipt {
  readonly ok: true;
  readonly action: "clean-reinstall-prepared";
  readonly evidenceId: string;
  readonly evidenceRoot: string;
  readonly evidenceManifestSha256: string;
  readonly preserved: readonly string[];
  readonly removed: readonly string[];
  readonly transactionId: string | null;
  readonly preparedAt: string;
}

function planFromInspection(inspection: SynchronizationTransactionInspection): RemoteSetupRepairPlan {
  const transaction = inspection.transaction;
  if (inspection.status === "absent" || inspection.status === "resolved") {
    return Object.freeze({ version: 1, action: "none", transactionId: transaction?.transactionId ?? null, lastCompletedPhase: inspection.lastCompletedPhase, desiredGeneration: transaction?.desiredGenerationIdentity ?? null, previousGeneration: transaction?.previousGenerationIdentity ?? null, rollbackAvailable: false, evidencePreserved: true, changes: Object.freeze(["No unresolved synchronization transaction requires repair."]) });
  }
  if (inspection.status === "unresolved" && inspection.integrityValid && inspection.hostBindingValid && inspection.rollbackAvailable && transaction?.previousGenerationAvailable) {
    return Object.freeze({
      version: 1,
      action: "restore-previous",
      transactionId: transaction.transactionId,
      lastCompletedPhase: inspection.lastCompletedPhase,
      desiredGeneration: transaction.desiredGenerationIdentity,
      previousGeneration: transaction.previousGenerationIdentity,
      rollbackAvailable: true,
      evidencePreserved: true,
      changes: Object.freeze([
        "Validate the immutable previous-generation snapshot and receipt chain.",
        "Restore only the recorded previous runtime, dispatcher, authorization, declarations, and canonical state.",
        "Download only public and signed verification artifacts required for certification.",
        "Verify the restored boundary and recorded generation identity.",
        "Preserve the failed transaction evidence and append repair audit evidence.",
      ]),
    });
  }
  return Object.freeze({
    version: 1,
    action: "clean-reinstall-required",
    transactionId: transaction?.transactionId ?? null,
    lastCompletedPhase: inspection.lastCompletedPhase,
    desiredGeneration: transaction?.desiredGenerationIdentity ?? null,
    previousGeneration: transaction?.previousGenerationIdentity ?? null,
    rollbackAvailable: false,
    evidencePreserved: true,
    changes: Object.freeze([
      "Copy every managed active artifact and failed transaction into immutable recovery evidence.",
      "Verify the evidence manifest before changing active paths.",
      "Remove only fixed OpsHaven-managed active paths; preserve audit history and transaction snapshots.",
      "Run one reviewed full installation and certify canonical readiness and the boundary.",
      "No automatic deletion or guessed generation selection is permitted.",
    ]),
  });
}

export async function inspectRemoteSetupRepair(
  config: RemoteSetupConfig,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteSetupRepairPlan> {
  return planFromInspection(await inspectRemoteSynchronizationTransaction(config, transport));
}

async function restorePublicVerificationMaterial(config: RemoteSetupConfig, transport: RemoteAdminTransport): Promise<void> {
  const transfers: readonly [string, string][] = [
    [config.remote.configPath, `${config.policyConfigPath}.dispatcher.json`],
    [`${config.remote.configPath}.capability.json`, `${config.policyConfigPath}.capability.json`],
    [`${config.remote.configPath}.declaration.json`, `${config.policyConfigPath}.declaration.json`],
    [`${config.remote.configPath}.declaration-binding.json`, `${config.policyConfigPath}.declaration-binding.json`],
    [`${config.remote.configPath}.response-public.pem`, `${config.policyConfigPath}.response-public.pem`],
    ["/etc/opshaven/approval-public.pem", config.local.operatorPublicKeyFile],
  ];
  for (const [remote, local] of transfers) {
    const result = await transport.download(remote, local);
    if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", `Restored public verification artifact could not be downloaded: ${remote}.`, true);
  }
}

function verifyRestoredInstalledState(installed: InstalledRemoteState, expectedGeneration: number | null): void {
  if (installed.status !== "complete" || installed.recordedIdentityMatches !== true || installed.generation === null) throw new OpsHavenError("POLICY_DENIED", "The restored generation is not a complete recorded canonical state.");
  if (expectedGeneration !== null && installed.generation !== expectedGeneration) throw new OpsHavenError("POLICY_DENIED", "The restored installation generation does not match the recorded previous generation.");
  for (const [label, digest] of Object.entries({
    runtime: installed.runtimeSha256,
    dispatcher: installed.dispatcherSha256,
    authorization: installed.capabilityIdentitySha256,
    declaration: installed.declarationSha256,
    policy: installed.policySha256,
  })) if (!digest) throw new OpsHavenError("POLICY_DENIED", `The restored ${label} identity is unavailable.`);
}

async function auditRepair(config: RemoteSetupConfig, plan: RemoteSetupRepairPlan, installed: InstalledRemoteState, action = plan.action): Promise<string> {
  const policy = await loadConfig(config.policyConfigPath);
  const evidenceDigest = sha256({
    action,
    transactionId: plan.transactionId,
    previousGeneration: plan.previousGeneration,
    installedGeneration: installed.generation,
    runtime: installed.runtimeSha256,
    dispatcher: installed.dispatcherSha256,
    authorization: installed.capabilityIdentitySha256,
    declaration: installed.declarationSha256,
    policy: installed.policySha256,
  });
  await new AuditLog(policy.audit.path).append({
    timestamp: new Date().toISOString(),
    requestId: randomBytes(12).toString("hex"),
    actor: "operator-cli",
    operation: "remote_setup_repair",
    resourceId: "remote.setup",
    mutation: action !== "none",
    dryRun: false,
    outcome: "success",
    evidenceDigest,
  });
  return evidenceDigest;
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

function cleanReinstallScript(config: RemoteSetupConfig, evidenceId: string): string {
  const request = JSON.stringify({
    evidenceId,
    evidenceParent: "/var/lib/opshaven/recovery-evidence",
    transactionPath: REMOTE_TRANSACTION_PATH,
    transactionRoot: REMOTE_TRANSACTION_ROOT,
    hostBindingSha256: synchronizationHostBinding(config),
    paths: managedActivePaths(config),
  });
  return `import hashlib,json,os,pathlib,shutil,stat,tempfile,datetime\nR=json.loads(${JSON.stringify(request)})\ndef fail(message): raise RuntimeError(message)\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef digest_file(path,maximum=33554432):\n info=os.lstat(path)\n if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size>maximum: fail('unsafe managed evidence file')\n h=hashlib.sha256()\n with open(path,'rb') as handle:\n  while True:\n   chunk=handle.read(1048576)\n   if not chunk: break\n   h.update(chunk)\n return h.hexdigest()\ndef digest_tree(root):\n root=pathlib.Path(root)\n if root.is_symlink() or not root.is_dir(): fail('unsafe managed evidence directory')\n files=[]\n for item in sorted(root.rglob('*')):\n  if item.is_symlink(): fail('managed evidence directory contains a symbolic link')\n  if item.is_dir(): continue\n  if not item.is_file(): fail('managed evidence directory contains an unsupported object')\n  files.append({'path':item.relative_to(root).as_posix(),'sha256':digest_file(item)})\n  if len(files)>4096: fail('managed evidence directory contains too many files')\n return hashlib.sha256(canonical(files).encode('utf-8')).hexdigest()\ndef atomic_json(value,path):\n path.parent.mkdir(parents=True,exist_ok=True)\n descriptor,temporary=tempfile.mkstemp(prefix=f'.{path.name}.opshaven-',dir=path.parent)\n try:\n  with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output: output.write(canonical(value)+'\\n'); output.flush(); os.fsync(output.fileno())\n  os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,path)\n finally:\n  if os.path.exists(temporary): os.unlink(temporary)\nevidence=pathlib.Path(R['evidenceParent'])/R['evidenceId']\nif evidence.exists(): fail('recovery evidence destination already exists')\nevidence.mkdir(parents=True,mode=0o700); os.chmod(evidence,0o700); os.chown(evidence,0,0)\nentries=[]; preserved=[]\nfor raw in [*R['paths'],R['transactionPath']]:\n source=pathlib.Path(raw); destination=evidence/'active'/pathlib.Path(raw.lstrip('/'))\n if not source.exists(): entries.append({'path':raw,'present':False,'kind':'absent','digest':None}); continue\n if source.is_symlink(): fail('managed active path is a symbolic link')\n destination.parent.mkdir(parents=True,exist_ok=True)\n if source.is_dir(): shutil.copytree(source,destination,symlinks=False); kind='directory'; digest=digest_tree(source)\n elif source.is_file(): shutil.copy2(source,destination,follow_symlinks=False); kind='file'; digest=digest_file(source)\n else: fail('managed active path has unsupported type')\n entries.append({'path':raw,'present':True,'kind':kind,'digest':digest}); preserved.append(raw)\ntransaction_id=None; transaction_path=pathlib.Path(R['transactionPath'])\nif transaction_path.exists():\n try:\n  with open(transaction_path,'r',encoding='utf-8') as handle: transaction=json.load(handle)\n  transaction_id=transaction.get('transactionId') if isinstance(transaction.get('transactionId'),str) else None\n  if transaction_id and len(transaction_id)==32:\n   history=pathlib.Path(R['transactionRoot'])/transaction_id\n   if history.exists():\n    if history.is_symlink() or not history.is_dir(): fail('transaction history is unsafe')\n    history_destination=evidence/'transaction-history'\n    shutil.copytree(history,history_destination,symlinks=False)\n    entries.append({'path':str(history),'present':True,'kind':'directory','digest':digest_tree(history)})\n except (OSError,ValueError,AttributeError): pass\nmanifest={'version':1,'evidenceId':R['evidenceId'],'hostBindingSha256':R['hostBindingSha256'],'transactionId':transaction_id,'createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),'entries':entries}\nmanifest_sha=hashlib.sha256(canonical(manifest).encode('utf-8')).hexdigest(); manifest['manifestSha256']=manifest_sha; atomic_json(manifest,evidence/'evidence-manifest.json')\nwith open(evidence/'evidence-manifest.json','r',encoding='utf-8') as handle: verified=json.load(handle)\nrecorded=verified.pop('manifestSha256',None)\nif recorded!=hashlib.sha256(canonical(verified).encode('utf-8')).hexdigest(): fail('recovery evidence manifest verification failed')\nremoved=[]\nfor raw in R['paths']:\n target=pathlib.Path(raw)\n if not target.exists(): continue\n if target.is_symlink(): fail('refusing symlinked active path during clean reinstall preparation')\n if target.is_dir(): shutil.rmtree(target)\n elif target.is_file(): target.unlink()\n else: fail('active path has unsupported type')\n removed.append(raw)\nif transaction_path.exists():\n if transaction_path.is_symlink() or not transaction_path.is_file(): fail('transaction path became unsafe')\n transaction_path.unlink(); removed.append(R['transactionPath'])\nprint(canonical({'ok':True,'action':'clean-reinstall-prepared','evidenceId':R['evidenceId'],'evidenceRoot':str(evidence),'evidenceManifestSha256':manifest_sha,'preserved':preserved,'removed':removed,'transactionId':transaction_id,'preparedAt':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')}))\n`;
}

function parseCleanPreparation(stdout: string, evidenceId: string): CleanReinstallPreparationReceipt {
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
  const paths = (input: unknown[]): readonly string[] => Object.freeze(input.map((item) => {
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
  const inspection = await inspectRemoteSynchronizationTransaction(config, transport);
  const plan = planFromInspection(inspection);
  if (plan.action !== "clean-reinstall-required") throw new OpsHavenError("POLICY_DENIED", "A reviewed clean reinstall is not the selected recovery action.", false, { repairPlan: plan });
  const evidenceId = randomBytes(16).toString("hex");
  const result = await transport.runPython(cleanReinstallScript(config, evidenceId), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Failed-state evidence could not be preserved safely. No clean reinstall was started.", true, { cleanReinstallDebug: result.stderr.replace(/[\r\n\u001b\u009b]/g, " ").slice(0, 500) });
  const receipt = parseCleanPreparation(result.stdout, evidenceId);
  const after = await readInstalledRemoteState(config, transport);
  if (after.status !== "absent") throw new OpsHavenError("POLICY_DENIED", "Clean reinstall preparation did not reach an empty active installation state.", false, { evidenceRoot: receipt.evidenceRoot });
  return receipt;
}

export async function repairRemoteSetup(
  config: RemoteSetupConfig,
  approved: boolean,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteSetupRepairReceipt> {
  const inspection = await inspectRemoteSynchronizationTransaction(config, transport);
  const plan = planFromInspection(inspection);
  if (plan.action === "none") {
    const installed = await readInstalledRemoteState(config, transport);
    const auditEvidenceDigest = await auditRepair(config, plan, installed);
    return Object.freeze({ ok: true, action: "none", transactionId: plan.transactionId, restoredGenerationIdentity: plan.previousGeneration, installedGeneration: installed.generation, boundary: null, auditEvidenceDigest, repairedAt: new Date().toISOString() });
  }
  if (plan.action === "clean-reinstall-required") throw new OpsHavenError("POLICY_DENIED", "No verified previous generation is available for automatic restoration. Preserve the evidence and run the reviewed clean reinstall flow.", false, { repairPlan: plan, safeNextCommand: "opshaven setup repair --clean-reinstall --approve" });
  if (!approved) throw new OpsHavenError("POLICY_DENIED", "Synchronization repair requires explicit approval.", false, { repairPlan: plan });
  if (!inspection.transaction || !plan.transactionId) throw new OpsHavenError("POLICY_DENIED", "The reviewed repair transaction is unavailable.");
  const expectedInstalledGeneration = inspection.transaction.previousGenerationAvailable ? Math.max(1, (inspection.transaction as unknown as { previousInstallationGeneration?: number }).previousInstallationGeneration ?? 1) : null;
  const rollback = await rollbackRecordedSynchronization(config, plan.transactionId, plan.previousGeneration, transport);
  await restorePublicVerificationMaterial(config, transport);
  const boundary = await certifyRemoteBoundary(config);
  if (!boundary.ok) throw new OpsHavenError("POLICY_DENIED", "The restored generation failed security-boundary verification.");
  const installed = await readInstalledRemoteState(config, transport);
  verifyRestoredInstalledState(installed, expectedInstalledGeneration === 1 ? null : expectedInstalledGeneration);
  await advanceRemoteSynchronizationTransaction(config, plan.transactionId, "ROLLBACK_CLEANUP", undefined, transport);
  const auditEvidenceDigest = await auditRepair(config, plan, installed);
  return Object.freeze({
    ok: true,
    action: "restore-previous",
    transactionId: plan.transactionId,
    restoredGenerationIdentity: rollback.restoredGenerationIdentity,
    installedGeneration: installed.generation,
    boundary,
    auditEvidenceDigest,
    repairedAt: new Date().toISOString(),
  });
}
