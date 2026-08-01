import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { OpsHavenError } from "../errors.js";
import { readRegularFile } from "../safe-fs.js";
import type { RemoteSetupConfig } from "./remote.js";
import type { DesiredRemoteState } from "./state.js";
import { REMOTE_TRANSACTION_PATH } from "./transaction.js";
import { PinnedSshAdminTransport, type RemoteAdminTransport } from "./transport.js";

export interface RemoteDispatcherInstallResult {
  readonly ok: true;
  readonly transactionId: string;
  readonly dispatcherSha256: string;
  readonly runtimeTreeSha256: string;
  readonly changed: readonly string[];
  readonly dependencyInstall: false;
}

function digest(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function parseResult(stdout: string, transactionId: string, desiredDispatcherSha256: string): RemoteDispatcherInstallResult {
  let value: unknown;
  try { value = JSON.parse(stdout) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Dispatcher installer returned invalid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Dispatcher installer evidence is malformed.");
  const record = value as Record<string, unknown>;
  if (record.ok !== true || record.transactionId !== transactionId || record.dispatcherSha256 !== desiredDispatcherSha256
    || typeof record.runtimeTreeSha256 !== "string" || !/^[a-f0-9]{64}$/.test(record.runtimeTreeSha256)
    || record.dependencyInstall !== false || !Array.isArray(record.changed)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Dispatcher installer evidence is incomplete.");
  }
  const changed = record.changed.map((item) => {
    if (typeof item !== "string" || !item.startsWith("/") || item.length > 4096) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Dispatcher installer changed-path evidence is invalid.");
    return item;
  });
  return Object.freeze({
    ok: true,
    transactionId,
    dispatcherSha256: desiredDispatcherSha256,
    runtimeTreeSha256: record.runtimeTreeSha256,
    changed: Object.freeze(changed),
    dependencyInstall: false,
  });
}

export async function installRestrictedDispatcher(
  config: RemoteSetupConfig,
  desired: DesiredRemoteState,
  installedDispatcherSha256: string,
  transactionId: string,
  transport: RemoteAdminTransport = new PinnedSshAdminTransport(config),
): Promise<RemoteDispatcherInstallResult> {
  if (!/^[a-f0-9]{64}$/.test(installedDispatcherSha256)) throw new OpsHavenError("CONFIG_INVALID", "Installed dispatcher identity is unavailable.");
  if (!/^[a-f0-9]{32}$/.test(transactionId)) throw new OpsHavenError("CONFIG_INVALID", "Synchronization transaction identity is invalid.");
  const dispatcher = await readRegularFile(config.local.dispatcherPath, "Reviewed dispatcher", { maxBytes: 16 * 1024 * 1024, code: "POLICY_DENIED" });
  if (digest(dispatcher) !== desired.dispatcherSha256) throw new OpsHavenError("POLICY_DENIED", "Reviewed dispatcher changed after synchronization planning.");
  const stage = await fs.mkdtemp(path.join(tmpdir(), "opshaven-dispatcher-"));
  const remoteStage = `/tmp/${path.basename(stage)}`;
  const plan = Object.freeze({
    version: 1,
    stageRoot: remoteStage,
    transactionPath: REMOTE_TRANSACTION_PATH,
    transactionId,
    sourceSha: desired.sourceSha,
    runtimeRoot: config.remote.runtimeRoot,
    manifestPath: `${config.remote.stateDirectory}/runtime-manifest.json`,
    receiptPath: config.remote.receiptPath,
    dispatcherRelative: "src/remote/dispatcher.js",
    expectedDispatcherSha256: installedDispatcherSha256,
    desiredDispatcherSha256: desired.dispatcherSha256,
  });
  try {
    await Promise.all([
      fs.writeFile(path.join(stage, "dispatcher.js"), dispatcher, { mode: 0o700 }),
      fs.writeFile(path.join(stage, "plan.json"), `${JSON.stringify(plan)}\n`, { mode: 0o600 }),
      fs.copyFile(path.join(process.cwd(), "packaging", "remote-dispatcher-installer.py"), path.join(stage, "installer.py")),
    ]);
    const uploaded = await transport.upload(stage, "/tmp", true);
    if (uploaded.code !== 0) throw new OpsHavenError("SSH_FAILED", "Dispatcher staging upload failed.", true);
    const installed = await transport.runPrivileged(["/usr/bin/python3", `${remoteStage}/installer.py`, remoteStage], { timeoutMs: 60000, maximumBytes: 1048576 });
    if (installed.code !== 0) throw new OpsHavenError("SSH_FAILED", "Dispatcher activation failed safely. The synchronization transaction remains available for rollback.", true, { dispatcherDebug: installed.stderr.replace(/[\r\n\u001b\u009b]/g, " ").slice(0, 500) });
    return parseResult(installed.stdout, transactionId, desired.dispatcherSha256);
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}
