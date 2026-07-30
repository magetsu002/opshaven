#!/usr/bin/env node
import { promises as fs } from "node:fs";
import { AuditLog } from "./audit.js";
import { loadConfig } from "./config.js";
import { OperationService } from "./operations.js";

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}
function required(name: string): string {
  const value = flag(name);
  if (!value) throw new Error(`Missing ${name}.`);
  return value;
}
function configPath(): string { return flag("--config") ?? process.env.OPSHAVEN_CONFIG ?? ""; }
function command(): string { return process.argv[2] ?? "help"; }

async function regularFile(path: string, ownerOnly: boolean): Promise<{ exists: boolean; safe: boolean }> {
  try {
    const stat = await fs.lstat(path);
    return { exists: true, safe: stat.isFile() && !stat.isSymbolicLink() && (!ownerOnly || (stat.mode & 0o077) === 0) };
  } catch { return { exists: false, safe: false }; }
}

async function main(): Promise<void> {
  const selected = command();
  if (selected === "help") {
    process.stdout.write("OpsHaven commands: validate-config, diagnostics, verify-audit, approve-restart, approve-deploy, approve-rollback, print-mcp-config\n");
    return;
  }
  const path = configPath();
  if (!path) throw new Error("A configuration path is required.");
  const config = await loadConfig(path);
  if (selected === "validate-config") {
    process.stdout.write(`${JSON.stringify({ ok: true, version: config.version, policyVersion: config.policyVersion, resources: config.resources.size })}\n`);
    return;
  }
  if (selected === "verify-audit") {
    const result = await new AuditLog(config.audit.path).verify();
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = result.valid ? 0 : 1;
    return;
  }
  if (selected === "diagnostics") {
    const hosts = [...config.resources.values()].filter((item) => item.kind === "host");
    const hostFiles = await Promise.all(hosts.map(async (host) => ({ resourceId: host.id, knownHosts: await regularFile(host.knownHostsFile, false), identity: await regularFile(host.identityFile, true) })));
    const approvals = { secret: await regularFile(config.approvals.secretFile, true), privateKey: await regularFile(config.approvals.signingPrivateKeyFile, true), publicKey: await regularFile(config.approvals.verificationPublicKeyFile, false) };
    const ok = hostFiles.every((item) => item.knownHosts.safe && item.identity.safe) && approvals.secret.safe && approvals.privateKey.safe && approvals.publicKey.safe;
    process.stdout.write(`${JSON.stringify({ ok, policyVersion: config.policyVersion, hosts: hostFiles, approvals })}\n`);
    process.exitCode = ok ? 0 : 1;
    return;
  }
  if (selected === "print-mcp-config") {
    process.stdout.write(`${JSON.stringify({ mcpServers: { opshaven: { command: "opshaven-mcp", args: ["--config", path] } } }, null, 2)}\n`);
    return;
  }
  const service = new OperationService(config);
  const resourceId = required("--resource");
  const ttl = flag("--ttl-seconds");
  const ttlSeconds = ttl === undefined ? undefined : Number(ttl);
  if (ttl !== undefined && (!Number.isInteger(ttlSeconds) || (ttlSeconds as number) < 30 || (ttlSeconds as number) > 3600)) throw new Error("TTL must be 30-3600 seconds.");
  let operation: string;
  let args: Record<string, unknown>;
  if (selected === "approve-restart") { operation = "restart_service"; args = { resourceId, dryRun: false }; }
  else if (selected === "approve-deploy") {
    operation = "deploy_commit";
    args = { resourceId, commit: required("--commit"), dryRun: false, ...(flag("--expected-current") ? { expectedCurrentCommit: flag("--expected-current") } : {}) };
  } else if (selected === "approve-rollback") { operation = "rollback_deployment"; args = { resourceId, releaseId: required("--release"), dryRun: false }; }
  else throw new Error("Unknown command.");
  const approval = await service.createApproval(operation, args, ttlSeconds);
  process.stdout.write(`${JSON.stringify({ ok: true, operation, resourceId, expiresAt: approval.expiresAt, digest: approval.digest, approvalToken: approval.token })}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "Command failed safely."}\n`);
  process.exitCode = 1;
});
