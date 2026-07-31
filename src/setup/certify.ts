import { createHash } from "node:crypto";
import { loadConfig, type HostResource } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { buildSshArgs } from "../transport/ssh.js";
import { verifyBoundary, type BoundaryAssertion, type BoundaryReport } from "../boundary.js";
import type { RemoteSetupConfig } from "./remote.js";
import { PinnedSshAdminTransport, runSetupProcess, type RemoteAdminTransport, type SetupCommandResult } from "./transport.js";

export interface RemoteBoundaryReceipt {
  readonly ok: true;
  readonly certifiedAt: string;
  readonly boundarySha256: string;
  readonly assertions: readonly BoundaryAssertion[];
}

export interface BoundaryCertificationRuntime {
  verify(configPath: string): Promise<BoundaryReport>;
  runRestricted(host: HostResource, stdin: string): Promise<SetupCommandResult>;
  readonly admin: RemoteAdminTransport;
}

function host(config: Awaited<ReturnType<typeof loadConfig>>): HostResource {
  const found = [...config.resources.values()].find((item) => item.kind === "host");
  if (!found || found.kind !== "host") throw new OpsHavenError("CONFIG_INVALID", "Boundary certification requires one configured host resource.");
  return found;
}

function actualRuntime(setup: RemoteSetupConfig): BoundaryCertificationRuntime {
  return {
    verify: async (configPath) => await verifyBoundary(await loadConfig(configPath), configPath, "read-only"),
    runRestricted: async (resource, stdin) => await runSetupProcess("/usr/bin/ssh", buildSshArgs(resource), { stdin, timeoutMs: 30000, maximumBytes: 1048576 }),
    admin: new PinnedSshAdminTransport(setup),
  };
}

function structuredInvalid(result: SetupCommandResult): { passed: boolean; detail: string } {
  try {
    const parsed = JSON.parse(result.stdout) as Record<string, any>;
    const code = typeof parsed.error?.code === "string" && /^[A-Z_]{3,64}$/.test(parsed.error.code) ? parsed.error.code : "MISSING_CODE";
    return { passed: parsed.ok === false && code === "REMOTE_PROTOCOL_INVALID", detail: `structured ${code} (ssh=${result.code})` };
  } catch { return { passed: false, detail: `invalid JSON response (ssh=${result.code})` }; }
}

function secretFree(value: string): boolean {
  return !/(?:BEGIN [A-Z ]*PRIVATE KEY|Bearer\s+[A-Za-z0-9._-]+|password\s*[=:]|secret\s*[=:]|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,})/i.test(value);
}

function receiptScript(setup: RemoteSetupConfig, boundarySha256: string, certifiedAt: string): string {
  const input = JSON.stringify({ receipt: setup.remote.receiptPath, sourceSha: setup.expectedSourceSha, boundarySha256, certifiedAt });
  return `import json, os, pathlib, stat, tempfile\nrequest=json.loads(${JSON.stringify(input)})\npath=pathlib.Path(request['receipt'])\ninfo=os.lstat(path)\nif not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > 1048576: raise RuntimeError('unsafe setup receipt')\nwith open(path,'r',encoding='utf-8') as handle: receipt=json.load(handle)\nif receipt.get('version') != 1 or receipt.get('sourceSha') != request['sourceSha'] or not isinstance(receipt.get('runtimeTreeSha256'),str): raise RuntimeError('setup receipt does not match installed source')\nreceipt['certified']=True\nreceipt['certifiedAt']=request['certifiedAt']\nreceipt['boundarySha256']=request['boundarySha256']\nreceipt['certificationVersion']=1\ndescriptor, temporary=tempfile.mkstemp(prefix='.setup-receipt-',dir=path.parent)\ntry:\n    with os.fdopen(descriptor,'w',encoding='utf-8',newline='\\n') as output:\n        output.write(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\\n'); output.flush(); os.fsync(output.fileno())\n    os.chmod(temporary,0o600); os.chown(temporary,0,0); os.replace(temporary,path)\nfinally:\n    if os.path.exists(temporary): os.unlink(temporary)\nprint(json.dumps({'ok':True,'certifiedAt':request['certifiedAt'],'boundarySha256':request['boundarySha256']},sort_keys=True))\n`;
}

export async function certifyRemoteBoundary(setup: RemoteSetupConfig, injected?: BoundaryCertificationRuntime): Promise<RemoteBoundaryReceipt> {
  const runtime = injected ?? actualRuntime(setup);
  const config = await loadConfig(setup.policyConfigPath);
  const report = await runtime.verify(setup.policyConfigPath);
  const assertions: BoundaryAssertion[] = [...report.assertions];
  const sshArgs = buildSshArgs(host(config));
  const requiredOptions = ["ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no", "PermitLocalCommand=no", "RequestTTY=no"];
  assertions.push({ name: "client forwarding and PTY disabled", passed: requiredOptions.every((item) => sshArgs.includes(item)), detail: "fixed SSH client arguments" });
  const malformed = await runtime.runRestricted(host(config), "{\n");
  const malformedResult = structuredInvalid(malformed);
  assertions.push({ name: "malformed input returns structured denial", passed: malformedResult.passed, detail: malformedResult.detail });
  assertions.push({ name: "certification output contains no apparent secrets", passed: secretFree(`${malformed.stdout}\n${malformed.stderr}`), detail: "bounded secret-pattern scan" });
  const required = [
    "interactive shell denied",
    "arbitrary SSH commands denied",
    "artifact and capability hashes valid",
    "read-only mutations unavailable",
    "request replay denied",
    "request mutation denied",
    "response mutation denied",
    "host-key mismatch denied",
    "audit chain valid",
    "client forwarding and PTY disabled",
    "malformed input returns structured denial",
    "certification output contains no apparent secrets",
  ];
  const incomplete = required.filter((name) => !assertions.some((item) => item.name === name && item.passed));
  const failed = assertions.filter((item) => !item.passed);
  if (!report.ok || incomplete.length > 0 || failed.length > 0) {
    const details = new Map<string, string>();
    for (const name of incomplete) details.set(name, "required assertion did not pass");
    for (const item of failed) details.set(item.name, item.detail);
    const summary = [...details.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([name, detail]) => `${name}: ${detail}`).join("; ");
    throw new OpsHavenError("POLICY_DENIED", `Remote boundary certification failed (${summary || "unknown assertion"}); endpoint setup remains blocked.`);
  }
  const certifiedAt = new Date().toISOString();
  const canonical = JSON.stringify(assertions.map((item) => ({ detail: item.detail, name: item.name, passed: item.passed })).sort((a, b) => a.name.localeCompare(b.name)));
  const boundarySha256 = createHash("sha256").update(canonical).digest("hex");
  const updated = await runtime.admin.runPython(receiptScript(setup, boundarySha256, certifiedAt), true);
  if (updated.code !== 0) throw new OpsHavenError("SSH_FAILED", "Certified boundary could not be recorded remotely.", true);
  let receipt: unknown;
  try { receipt = JSON.parse(updated.stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote certification receipt is invalid."); }
  const record = receipt as Record<string, unknown>;
  if (record.ok !== true || record.boundarySha256 !== boundarySha256 || record.certifiedAt !== certifiedAt) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote certification receipt does not match local evidence.");
  return Object.freeze({ ok: true, certifiedAt, boundarySha256, assertions: Object.freeze(assertions) });
}

export async function readRemoteCertification(setup: RemoteSetupConfig, transport: RemoteAdminTransport = new PinnedSshAdminTransport(setup)): Promise<{ certified: boolean; boundarySha256: string | null; sourceSha: string | null }> {
  const script = `import json, os, pathlib, stat\npath=pathlib.Path(${JSON.stringify(setup.remote.receiptPath)})\ntry:\n    info=os.lstat(path)\n    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > 1048576: raise RuntimeError('unsafe receipt')\n    with open(path,'r',encoding='utf-8') as handle: receipt=json.load(handle)\n    print(json.dumps({'certified':receipt.get('certified') is True,'boundarySha256':receipt.get('boundarySha256'),'sourceSha':receipt.get('sourceSha')},sort_keys=True))\nexcept (OSError,ValueError,RuntimeError):\n    print(json.dumps({'certified':False,'boundarySha256':None,'sourceSha':None},sort_keys=True))\n`;
  const result = await transport.runPython(script, true);
  if (result.code !== 0) throw new OpsHavenError("SSH_FAILED", "Remote certification state could not be read.", true);
  try {
    const value = JSON.parse(result.stdout) as Record<string, unknown>;
    const boundarySha256 = typeof value.boundarySha256 === "string" && /^[a-f0-9]{64}$/.test(value.boundarySha256) ? value.boundarySha256 : null;
    const sourceSha = typeof value.sourceSha === "string" && /^[a-f0-9]{40}$/.test(value.sourceSha) ? value.sourceSha : null;
    return { certified: value.certified === true && boundarySha256 !== null && sourceSha === setup.expectedSourceSha, boundarySha256, sourceSha };
  } catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote certification state is malformed."); }
}
