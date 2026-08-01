import { OpsHavenError } from "../errors.js";
import type { RemoteSetupConfig } from "./remote.js";
import {
  REMOTE_TRANSACTION_PATH,
  synchronizationHostBinding,
  type RemoteSynchronizationTransaction,
  type SynchronizationPhase,
} from "./transaction.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export type SynchronizationTransactionStatus = "absent" | "resolved" | "unresolved" | "invalid";

export interface SynchronizationTransactionInspection {
  readonly status: SynchronizationTransactionStatus;
  readonly transaction: RemoteSynchronizationTransaction | null;
  readonly integrityValid: boolean;
  readonly hostBindingValid: boolean;
  readonly rollbackAvailable: boolean;
  readonly activeGenerationCertain: boolean;
  readonly lastCompletedPhase: SynchronizationPhase | null;
  readonly detail?: string;
}

const TERMINAL_PHASES = new Set<SynchronizationPhase>(["COMMIT", "CLEANUP", "ROLLBACK_COMMIT", "ROLLBACK_CLEANUP"]);
const PHASES: readonly SynchronizationPhase[] = [
  "INSPECT", "PLAN", "STAGE", "VERIFY_STAGED", "RECORD_PREVIOUS", "ACTIVATE", "VERIFY_ACTIVE", "COMMIT", "CLEANUP",
  "ROLLBACK_START", "RESTORE_PREVIOUS", "VERIFY_RESTORED", "ROLLBACK_COMMIT", "ROLLBACK_CLEANUP",
];

function script(config: RemoteSetupConfig): string {
  const request = JSON.stringify({ path: REMOTE_TRANSACTION_PATH, hostBindingSha256: synchronizationHostBinding(config) });
  return `import hashlib,json,os,pathlib,stat\nR=json.loads(${JSON.stringify(request)})\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef digest(value): return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()\npath=pathlib.Path(R['path'])\nif not path.exists(): print(canonical({'status':'absent'})); raise SystemExit(0)\ntry:\n info=os.lstat(path)\n if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size>2097152: raise RuntimeError('unsafe transaction file')\n with open(path,'r',encoding='utf-8') as handle: record=json.load(handle)\n integrity=record.pop('integritySha256',None); valid=isinstance(integrity,str) and len(integrity)==64 and digest(record)==integrity\n record['integritySha256']=integrity\n host=record.get('hostBindingSha256')==R['hostBindingSha256']\n phase=record.get('phase'); terminal=phase in ('COMMIT','CLEANUP','ROLLBACK_COMMIT','ROLLBACK_CLEANUP')\n snapshot=pathlib.Path(record.get('snapshotRoot','')) if isinstance(record.get('snapshotRoot'),str) else pathlib.Path('')\n rollback=bool(valid and host and record.get('previousGenerationAvailable') and snapshot.is_absolute() and snapshot.is_dir() and not snapshot.is_symlink() and (snapshot/'snapshot.json').is_file())\n certain=bool(valid and host and terminal)\n print(canonical({'status':'resolved' if certain else 'unresolved' if valid and host else 'invalid','transaction':record,'integrityValid':valid,'hostBindingValid':host,'rollbackAvailable':rollback,'activeGenerationCertain':certain,'lastCompletedPhase':phase}))\nexcept Exception as error:\n print(canonical({'status':'invalid','transaction':None,'integrityValid':False,'hostBindingValid':False,'rollbackAvailable':False,'activeGenerationCertain':False,'lastCompletedPhase':None,'detail':str(error)[:200]}))\n`;
}

function optionalText(value: unknown, pattern: RegExp): string | null {
  return typeof value === "string" && pattern.test(value) ? value : null;
}

function parseTransaction(value: unknown): RemoteSynchronizationTransaction | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const phase = optionalText(record.phase, /^[A-Z_]+$/) as SynchronizationPhase | null;
  if (record.version !== 1 || !phase || !PHASES.includes(phase)
    || !optionalText(record.transactionId, /^[a-f0-9]{32}$/)
    || !optionalText(record.hostBindingSha256, /^[a-f0-9]{64}$/)
    || !optionalText(record.desiredGenerationIdentity, /^[a-f0-9]{64}$/)
    || !(record.previousGenerationIdentity === null || optionalText(record.previousGenerationIdentity, /^[a-f0-9]{64}$/))
    || typeof record.previousGenerationAvailable !== "boolean"
    || typeof record.snapshotRoot !== "string" || !record.snapshotRoot.startsWith("/var/lib/opshaven/transactions/")
    || typeof record.changeType !== "string"
    || typeof record.createdAt !== "string" || typeof record.updatedAt !== "string"
    || !optionalText(record.integritySha256, /^[a-f0-9]{64}$/)) return null;
  return Object.freeze(record as unknown as RemoteSynchronizationTransaction);
}

export async function inspectRemoteSynchronizationTransaction(
  config: RemoteSetupConfig,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<SynchronizationTransactionInspection> {
  const result = await transport.runPython(script(config), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Synchronization transaction state could not be inspected safely.", true);
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Synchronization transaction inspection returned invalid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Synchronization transaction inspection is malformed.");
  const record = value as Record<string, unknown>;
  if (record.status === "absent") return Object.freeze({ status: "absent", transaction: null, integrityValid: true, hostBindingValid: true, rollbackAvailable: false, activeGenerationCertain: true, lastCompletedPhase: null });
  if (record.status !== "resolved" && record.status !== "unresolved" && record.status !== "invalid") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Synchronization transaction status is invalid.");
  const transaction = parseTransaction(record.transaction);
  const phase = typeof record.lastCompletedPhase === "string" && PHASES.includes(record.lastCompletedPhase as SynchronizationPhase) ? record.lastCompletedPhase as SynchronizationPhase : null;
  const inspection: SynchronizationTransactionInspection = Object.freeze({
    status: record.status,
    transaction,
    integrityValid: record.integrityValid === true,
    hostBindingValid: record.hostBindingValid === true,
    rollbackAvailable: record.rollbackAvailable === true,
    activeGenerationCertain: record.activeGenerationCertain === true,
    lastCompletedPhase: phase,
    ...(typeof record.detail === "string" ? { detail: record.detail.slice(0, 200) } : {}),
  });
  if (inspection.status !== "invalid" && !transaction) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Synchronization transaction evidence is incomplete.");
  if (inspection.status === "resolved" && transaction && !TERMINAL_PHASES.has(transaction.phase)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Resolved synchronization transaction has a non-terminal phase.");
  return inspection;
}
