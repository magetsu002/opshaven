import { OpsHavenError } from "../errors.js";
import type { RemoteSetupConfig } from "./remote.js";
import { REMOTE_STATE_PATH } from "./state.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export interface RemoteCleanupReceipt {
  readonly ok: true;
  readonly action: "rollback" | "uninstall";
  readonly completedAt: string;
  readonly restored: readonly string[];
  readonly removed: readonly string[];
  readonly preserved: readonly string[];
}

function fixedPaths(setup: RemoteSetupConfig): string[] {
  return [
    setup.remote.runtimeRoot,
    `${setup.remote.stateDirectory}/runtime-manifest.json`,
    setup.remote.configPath,
    setup.remote.wrapperPath,
    `/home/${setup.remote.account}/.ssh/authorized_keys`,
    "/etc/opshaven/approval-public.pem",
    `${setup.remote.configPath}.capability.json`,
    `${setup.remote.configPath}.declaration.json`,
    `${setup.remote.configPath}.declaration-binding.json`,
    `${setup.remote.configPath}.response-private.pem`,
    `${setup.remote.configPath}.response-public.pem`,
    REMOTE_STATE_PATH,
  ];
}

function rollbackScript(setup: RemoteSetupConfig): string {
  const request = JSON.stringify({
    receipt: setup.remote.receiptPath,
    sourceSha: setup.expectedSourceSha,
    allowed: fixedPaths(setup),
    runtimeRoot: setup.remote.runtimeRoot,
    runtimeManifest: `${setup.remote.stateDirectory}/runtime-manifest.json`,
  });
  return `import hashlib, json, os, pathlib, shutil, stat, tempfile, datetime\nrequest=json.loads(${JSON.stringify(request)})\ndef fail(message): raise RuntimeError(message)\ndef regular(path, maximum=2097152):\n    info=os.lstat(path)\n    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > maximum: fail('unsafe receipt')\ndef hash_file(path):\n    digest=hashlib.sha256()\n    with open(path,'rb') as handle:\n        while True:\n            chunk=handle.read(1048576)\n            if not chunk: break\n            digest.update(chunk)\n    return digest.hexdigest()\ndef runtime_manifest(root):\n    if root.is_symlink() or not root.is_dir(): fail('restored runtime root is unsafe')\n    files=[]\n    for candidate in sorted(root.rglob('*')):\n        if candidate.is_symlink(): fail('restored runtime contains a symbolic link')\n        if candidate.is_dir(): continue\n        if not candidate.is_file(): fail('restored runtime contains an unsupported object')\n        relative=candidate.relative_to(root).as_posix()\n        files.append({'executable':relative in ('src/remote/dispatcher.js','src/remote/read-only-dispatcher.js'),'path':relative,'sha256':hash_file(candidate)})\n        if len(files)>4096: fail('restored runtime contains too many files')\n    if not files: fail('restored runtime is empty')\n    encoded=json.dumps(files,separators=(',',':')).encode('utf-8')\n    return {'version':1,'files':files,'treeSha256':hashlib.sha256(encoded).hexdigest()}\ndef atomic_json(value,destination):\n    destination.parent.mkdir(parents=True,exist_ok=True)\n    descriptor,temporary=tempfile.mkstemp(prefix=f'.{destination.name}.opshaven-',dir=destination.parent)\n    try:\n        with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output:\n            output.write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\\n'); output.flush(); os.fsync(output.fileno())\n        os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,destination)\n    finally:\n        if os.path.exists(temporary): os.unlink(temporary)\nreceipt_path=pathlib.Path(request['receipt']); regular(receipt_path)\nwith open(receipt_path,'r',encoding='utf-8') as handle: receipt=json.load(handle)\nif receipt.get('version') != 1 or receipt.get('sourceSha') != request['sourceSha']: fail('receipt source mismatch')\nbackup_root=pathlib.Path(receipt.get('backupRoot','')); expected_parent=pathlib.Path('/var/lib/opshaven/backups')\nif not backup_root.is_absolute() or backup_root.parent != expected_parent or not backup_root.is_dir() or backup_root.is_symlink(): fail('backup root is invalid')\nallowed=set(request['allowed']); changed=receipt.get('changed')\nif not isinstance(changed,list) or any(not isinstance(item,str) or item not in allowed for item in changed): fail('receipt changed-path evidence is invalid')\nrestored=[]; removed=[]\nfor raw in reversed(changed):\n    destination=pathlib.Path(raw); backup=backup_root / raw.lstrip('/')\n    if destination.is_symlink(): fail('refusing symlinked rollback destination')\n    if backup.exists():\n        if backup.is_symlink(): fail('refusing symlinked backup')\n        if destination.exists():\n            if destination.is_dir(): shutil.rmtree(destination)\n            else: destination.unlink()\n        destination.parent.mkdir(parents=True,exist_ok=True); shutil.move(str(backup),str(destination)); restored.append(raw)\n    elif destination.exists():\n        if destination.is_dir(): shutil.rmtree(destination)\n        elif destination.is_file(): destination.unlink()\n        else: fail('unsupported rollback destination')\n        removed.append(raw)\nruntime_root=pathlib.Path(request['runtimeRoot']); runtime_manifest_path=pathlib.Path(request['runtimeManifest'])\nif request['runtimeRoot'] in changed:\n    if runtime_root.exists():\n        atomic_json(runtime_manifest(runtime_root),runtime_manifest_path)\n        if request['runtimeManifest'] not in restored: restored.append(request['runtimeManifest'])\n    elif runtime_manifest_path.exists():\n        if runtime_manifest_path.is_symlink() or not runtime_manifest_path.is_file(): fail('unsafe runtime manifest rollback destination')\n        runtime_manifest_path.unlink(); removed.append(request['runtimeManifest'])\nreceipt['certified']=False; receipt['rollback']={'completed':True,'completedAt':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),'restored':restored,'removed':removed}\ndescriptor,temporary=tempfile.mkstemp(prefix='.setup-receipt-',dir=receipt_path.parent)\ntry:\n    with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output:\n        output.write(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\\n'); output.flush(); os.fsync(output.fileno())\n    os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,receipt_path)\nfinally:\n    if os.path.exists(temporary): os.unlink(temporary)\nprint(json.dumps({'ok':True,'action':'rollback','completedAt':receipt['rollback']['completedAt'],'restored':restored,'removed':removed,'preserved':[]},sort_keys=True))\n`;
}

function uninstallScript(setup: RemoteSetupConfig): string {
  const request = JSON.stringify({ account: setup.remote.account, state: setup.remote.stateDirectory, paths: fixedPaths(setup), forced: `${setup.remote.wrapperPath} --config ${setup.remote.configPath}` });
  return `import json, os, pathlib, pwd, grp, shutil, stat, subprocess, datetime\nrequest=json.loads(${JSON.stringify(request)})\ndef fail(message): raise RuntimeError(message)\ndef remove_path(path,removed):\n    if not path.exists(): return\n    info=os.lstat(path)\n    if stat.S_ISLNK(info.st_mode): fail('refusing symlinked uninstall path')\n    if path.is_dir(): shutil.rmtree(path)\n    elif path.is_file(): path.unlink()\n    else: fail('unsupported uninstall path')\n    removed.append(str(path))\nremoved=[]; preserved=[]; authorized=pathlib.Path('/home')/request['account']/'.ssh'/'authorized_keys'\nif authorized.exists():\n    info=os.lstat(authorized)\n    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size>1048576: fail('unsafe authorized_keys')\n    lines=authorized.read_text(encoding='utf-8').splitlines(); kept=[line for line in lines if not (line.startswith('restrict,command=') and request['forced'] in line)]\n    if kept: authorized.write_text('\\n'.join(kept)+'\\n',encoding='utf-8'); os.chmod(authorized,0o600); os.chown(authorized,info.st_uid,info.st_gid); preserved.append(str(authorized))\n    else: authorized.unlink(); removed.append(str(authorized))\nfor raw in request['paths']:\n    path=pathlib.Path(raw)\n    if path != authorized: remove_path(path,removed)\nstate=pathlib.Path(request['state']); remove_path(state,removed)\nhome=pathlib.Path('/home')/request['account']\ntry: entry=pwd.getpwnam(request['account'])\nexcept KeyError: entry=None\nif entry is not None:\n    groups={group.gr_name for group in grp.getgrall() if request['account'] in group.gr_mem}; groups.add(grp.getgrgid(entry.pw_gid).gr_name)\n    remaining=[str(item) for item in home.rglob('*') if item.exists()] if home.exists() else []\n    if entry.pw_dir==str(home) and entry.pw_shell=='/bin/bash' and not groups & {'sudo','wheel','docker','lxd'} and not remaining:\n        result=subprocess.run(['/usr/sbin/userdel','--remove',request['account']],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)\n        if result.returncode!=0: fail('restricted account removal failed')\n        removed.append(request['account'])\n    else: preserved.append(request['account'])\ncompleted=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')\nprint(json.dumps({'ok':True,'action':'uninstall','completedAt':completed,'restored':[],'removed':removed,'preserved':preserved},sort_keys=True))\n`;
}

function parseReceipt(stdout: string, action: "rollback" | "uninstall"): RemoteCleanupReceipt {
  let value: unknown;
  try { value = JSON.parse(stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `Remote ${action} receipt is invalid JSON.`); }
  if (!value || typeof value !== "object") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `Remote ${action} receipt is malformed.`);
  const record = value as Record<string, unknown>;
  if (record.ok !== true || record.action !== action || typeof record.completedAt !== "string" || !Array.isArray(record.restored) || !Array.isArray(record.removed) || !Array.isArray(record.preserved)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `Remote ${action} receipt is incomplete.`);
  const list = (input: unknown[]): readonly string[] => Object.freeze(input.map((item) => {
    if (typeof item !== "string" || item.length === 0 || item.length > 4096) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `Remote ${action} receipt contains invalid path evidence.`);
    return item;
  }));
  return Object.freeze({ ok: true, action, completedAt: record.completedAt, restored: list(record.restored), removed: list(record.removed), preserved: list(record.preserved) });
}

export async function rollbackRemoteSetup(setup: RemoteSetupConfig, approved: boolean, transport: RemoteAdminTransport = new PinnedSshAdminTransport(setup)): Promise<RemoteCleanupReceipt> {
  if (!approved) throw new OpsHavenError("POLICY_DENIED", "Rollback requires explicit approval.");
  const result = await transport.runPython(rollbackScript(setup), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", `Remote rollback failed safely: ${result.stderr.trim() || "no diagnostic"}.`, true);
  return parseReceipt(result.stdout, "rollback");
}

export async function uninstallRemoteSetup(setup: RemoteSetupConfig, approved: boolean, transport: RemoteAdminTransport = new PinnedSshAdminTransport(setup)): Promise<RemoteCleanupReceipt> {
  if (!approved) throw new OpsHavenError("POLICY_DENIED", "Uninstall requires explicit approval.");
  const result = await transport.runPython(uninstallScript(setup), true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", `Remote uninstall failed safely: ${result.stderr.trim() || "no diagnostic"}.`, true);
  return parseReceipt(result.stdout, "uninstall");
}
