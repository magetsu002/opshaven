import { access, lstat } from "node:fs/promises";
import type { OpsHavenConfig } from "../config/schema.js";
import { verifyAuditLog } from "../security/audit.js";
import { RestrictedSshTransport } from "../transport/ssh.js";

export type DiagnosticStatus = "pass" | "fail" | "warning";
export type DiagnosticCheck = Readonly<{
  name: string;
  status: DiagnosticStatus;
  detail: string;
}>;
export type DiagnosticReport = Readonly<{
  ok: boolean;
  checks: readonly DiagnosticCheck[];
}>;

export type DoctorDependencies = Readonly<{
  accessPath?: (path: string) => Promise<void>;
  inspectPath?: (path: string) => Promise<Readonly<{ isFile(): boolean; isSymbolicLink(): boolean }>>;
  verifyHost?: (host: OpsHavenConfig["hosts"][number]) => Promise<void>;
  verifyAudit?: (path: string) => Promise<Readonly<{ valid: boolean; records: number; error?: string }>>;
  environment?: NodeJS.ProcessEnv;
}>;

async function checkRegularFile(
  path: string,
  label: string,
  inspectPath: NonNullable<DoctorDependencies["inspectPath"]>
): Promise<DiagnosticCheck> {
  try {
    const info = await inspectPath(path);
    if (info.isSymbolicLink() || !info.isFile()) {
      return { name: label, status: "fail", detail: "Path must be a non-symlink regular file" };
    }
    return { name: label, status: "pass", detail: "Regular file present" };
  } catch {
    return { name: label, status: "fail", detail: "Path is unavailable" };
  }
}

export async function runDoctor(config: OpsHavenConfig, dependencies: DoctorDependencies = {}): Promise<DiagnosticReport> {
  const accessPath = dependencies.accessPath ?? (async (path: string) => await access(path));
  const inspectPath = dependencies.inspectPath ?? lstat;
  const transport = new RestrictedSshTransport();
  const verifyHost = dependencies.verifyHost ?? (async (host) => await transport.verifyPinnedHostKey(host));
  const verifyAudit = dependencies.verifyAudit ?? verifyAuditLog;
  const environment = dependencies.environment ?? process.env;
  const checks: DiagnosticCheck[] = [];

  for (const executable of ["/usr/bin/ssh", "/usr/bin/ssh-keygen", process.execPath]) {
    try {
      await accessPath(executable);
      checks.push({ name: `executable:${executable}`, status: "pass", detail: "Executable is available" });
    } catch {
      checks.push({ name: `executable:${executable}`, status: "fail", detail: "Executable is unavailable" });
    }
  }

  for (const host of config.hosts) {
    checks.push(await checkRegularFile(host.identityFile, `identity:${host.id}`, inspectPath));
    checks.push(await checkRegularFile(host.knownHostsFile, `known-hosts:${host.id}`, inspectPath));
    try {
      await verifyHost(host);
      checks.push({ name: `host-key:${host.id}`, status: "pass", detail: "Pinned host key matches" });
    } catch {
      checks.push({ name: `host-key:${host.id}`, status: "fail", detail: "Pinned host key verification failed" });
    }
  }

  const approvalKey = environment[config.approvals.keyEnvironmentVariable];
  checks.push({
    name: "approval-key",
    status: approvalKey !== undefined && approvalKey.length >= 32 ? "pass" : "fail",
    detail: approvalKey !== undefined && approvalKey.length >= 32 ? "Approval key is present" : "Approval key is missing or short"
  });

  const audit = await verifyAudit(config.audit.path);
  checks.push({
    name: "audit-chain",
    status: audit.valid ? "pass" : "fail",
    detail: audit.valid ? `${audit.records} record(s) verified` : audit.error ?? "Audit verification failed"
  });

  return { ok: checks.every((check) => check.status !== "fail"), checks };
}
