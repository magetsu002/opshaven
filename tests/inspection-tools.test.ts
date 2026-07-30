import assert from "node:assert/strict";
import test from "node:test";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { parseConfig } from "../src/config.js";
import { handleInspection } from "../src/remote/handlers.js";
import type { CommandRunner } from "../src/remote/runner.js";

async function fixture() {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-inspect-"));
  const envFile = path.join(root, "runtime.env");
  const backupFile = path.join(root, "backup.json");
  await fs.writeFile(envFile, "PUBLIC_MODE=production\nDATABASE_PASSWORD=do-not-return\n");
  await fs.writeFile(backupFile, JSON.stringify({ backupId: "backup-1", lastBackupAt: new Date().toISOString(), lastRestoreTestAt: new Date().toISOString(), verified: true, bytes: 1024 }));
  const config = parseConfig({ version: 1, policyVersion: "v1", limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 }, audit: { path: path.join(root, "audit.jsonl") }, approvals: { directory: path.join(root, "approvals"), secretFile: path.join(root, "secret"), signingPrivateKeyFile: path.join(root, "private.pem"), verificationPublicKeyFile: path.join(root, "public.pem"), remoteUsedDirectory: path.join(root, "remote-used"), defaultTtlSeconds: 300 }, secretFingerprints: [], resources: [
    { id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id", connectTimeoutMs: 5000 },
    { id: "app.web", kind: "application", hostId: "host.main", runtimeConfigKeys: ["PUBLIC_MODE", "DATABASE_PASSWORD", "MISSING_KEY"], environmentFile: envFile },
    { id: "svc.proxy", kind: "service", hostId: "host.main", unit: "proxy.service" },
    { id: "svc.web", kind: "service", hostId: "host.main", unit: "web.service" },
    { id: "proxy.web", kind: "proxy", hostId: "host.main", provider: "nginx", serviceId: "svc.proxy", publicNames: ["example.invalid"] },
    { id: "monitor.web", kind: "monitoring", hostId: "host.main", serviceIds: ["svc.web"], probeIds: [] },
    { id: "backup.web", kind: "backup", hostId: "host.main", statusFile: backupFile, maximumAgeHours: 24 }
  ] });
  const runner: CommandRunner = { async run(executable, args) {
    if (executable === "/usr/sbin/ufw") return { exitCode: 0, stdout: "ALLOW token=planted-firewall-secret" };
    if (executable === "/usr/bin/journalctl") return { exitCode: 0, stdout: "password=planted-log-secret\nhealthy" };
    if (executable === "/usr/bin/systemctl") return { exitCode: 0, stdout: `Id=${String(args[1])}\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=12\nExecMainStatus=0\nActiveEnterTimestamp=now\n` };
    return { exitCode: 0, stdout: "" };
  } };
  return { config, runner };
}
function request(operation: any, resourceId: string, args: Record<string, string | number | boolean> = { resourceId }) {
  return { version: 1 as const, requestId: "req", operation, resourceId, args, limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 } };
}

test("runtime configuration reports presence without values", async () => {
  const { config, runner } = await fixture();
  const result = await handleInspection({ config, runner }, request("get_runtime_config_status", "app.web"));
  assert.equal(JSON.stringify(result).includes("do-not-return"), false);
  assert.equal((result.keys as any).DATABASE_PASSWORD.present, true);
  assert.equal((result.keys as any).MISSING_KEY.present, false);
});

test("network and log summaries redact planted secrets", async () => {
  const { config, runner } = await fixture();
  const proxy = await handleInspection({ config, runner }, request("get_reverse_proxy_summary", "proxy.web"));
  assert.equal((proxy.service as any).activeState, "active");
  const firewall = await handleInspection({ config, runner }, request("get_firewall_summary", "host.main"));
  assert.equal(JSON.stringify(firewall).includes("planted-firewall-secret"), false);
  const logs = await handleInspection({ config, runner }, request("get_redacted_logs", "svc.web", { resourceId: "svc.web", lines: 20, sinceMinutes: 10 }));
  assert.equal(JSON.stringify(logs).includes("planted-log-secret"), false);
});

test("monitoring, backup, and restore readiness return structured evidence", async () => {
  const { config, runner } = await fixture();
  const monitoring = await handleInspection({ config, runner }, request("get_monitoring_status", "monitor.web"));
  assert.equal((monitoring.services as any)["svc.web"].activeState, "active");
  const backup = await handleInspection({ config, runner }, request("get_backup_status", "backup.web"));
  assert.equal(backup.fresh, true);
  const restore = await handleInspection({ config, runner }, request("get_restore_readiness", "backup.web"));
  assert.equal(restore.ready, true);
});
