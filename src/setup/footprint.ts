import { OpsHavenError } from "../errors.js";
import type { RemoteSetupConfig } from "./remote.js";
import { REMOTE_STATE_PATH } from "./state.js";
import { REMOTE_TRANSACTION_PATH } from "./transaction.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export type RemoteFootprintKind = "empty" | "canonical-pair" | "legacy" | "partial" | "unsafe";

export interface RemoteManagedFootprint {
  readonly version: 1;
  readonly kind: RemoteFootprintKind;
  readonly present: readonly string[];
  readonly missing: readonly string[];
  readonly receiptPresent: boolean;
  readonly statePresent: boolean;
  readonly transactionPresent: boolean;
  readonly detail: string;
}

function inspectionScript(config: RemoteSetupConfig): string {
  const request = JSON.stringify({
    receipt: config.remote.receiptPath,
    state: REMOTE_STATE_PATH,
    transaction: REMOTE_TRANSACTION_PATH,
    runtimeManifest: `${config.remote.stateDirectory}/runtime-manifest.json`,
    runtimeRoot: config.remote.runtimeRoot,
    config: config.remote.configPath,
    capability: `${config.remote.configPath}.capability.json`,
    declaration: `${config.remote.configPath}.declaration.json`,
    wrapper: config.remote.wrapperPath,
    publicKey: "/etc/opshaven/approval-public.pem",
  });
  return `import json,os,pathlib,stat\nR=json.loads(${JSON.stringify(request)})\ndef canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'))\ndef classify(path):\n p=pathlib.Path(path)\n try: info=os.lstat(p)\n except OSError: return 'missing'\n if stat.S_ISLNK(info.st_mode): return 'unsafe'\n if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode): return 'present'\n return 'unsafe'\nvalues={key:classify(value) for key,value in R.items()}\nunsafe=sorted([R[key] for key,value in values.items() if value=='unsafe'])\npresent=sorted([R[key] for key,value in values.items() if value=='present'])\nmissing=sorted([R[key] for key,value in values.items() if value=='missing'])\nreceipt=values['receipt']=='present'; state=values['state']=='present'; transaction=values['transaction']=='present'\nmanaged=[key for key in values if key not in ('receipt','state','transaction')]\nmanaged_present=any(values[key]=='present' for key in managed)\nif unsafe: kind='unsafe'; detail='one or more managed paths are unsafe'\nelif not present: kind='empty'; detail='no OpsHaven-managed remote state was found'\nelif receipt and state: kind='canonical-pair'; detail='canonical receipt and state records are present'\nelif not receipt and not state and managed_present: kind='legacy'; detail='managed runtime artifacts exist without canonical generation records'\nelse: kind='partial'; detail='canonical generation identity is partial'\nprint(canonical({'version':1,'kind':kind,'present':present,'missing':missing,'receiptPresent':receipt,'statePresent':state,'transactionPresent':transaction,'detail':detail}))\n`;
}

export async function inspectRemoteManagedFootprint(
  config: RemoteSetupConfig,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteManagedFootprint> {
  const result = await transport.runPython(inspectionScript(config), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Remote installation footprint could not be inspected safely.", true);
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote installation footprint response is not valid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote installation footprint response is malformed.");
  const record = value as Record<string, unknown>;
  const kinds: readonly RemoteFootprintKind[] = ["empty", "canonical-pair", "legacy", "partial", "unsafe"];
  if (record.version !== 1 || typeof record.kind !== "string" || !kinds.includes(record.kind as RemoteFootprintKind)
    || !Array.isArray(record.present) || !Array.isArray(record.missing)
    || typeof record.receiptPresent !== "boolean" || typeof record.statePresent !== "boolean"
    || typeof record.transactionPresent !== "boolean" || typeof record.detail !== "string") {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote installation footprint evidence is incomplete.");
  }
  const paths = (items: unknown[]): readonly string[] => Object.freeze(items.map((item) => {
    if (typeof item !== "string" || !item.startsWith("/") || item.length > 4096) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote installation footprint contains an invalid path.");
    return item;
  }));
  return Object.freeze({
    version: 1,
    kind: record.kind as RemoteFootprintKind,
    present: paths(record.present),
    missing: paths(record.missing),
    receiptPresent: record.receiptPresent,
    statePresent: record.statePresent,
    transactionPresent: record.transactionPresent,
    detail: record.detail.slice(0, 200),
  });
}
