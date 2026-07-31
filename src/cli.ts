#!/usr/bin/env node
import { promises as fs } from "node:fs";
import { AuditLog } from "./audit.js";
import { formatBoundaryReport, verifyBoundary } from "./boundary.js";
import { compareCapabilityDeclarations, formatCapabilityComparison, loadCapabilityDeclaration } from "./capability-declaration.js";
import { loadConfig } from "./config.js";
import { OperationService } from "./operations.js";
import { runRemoteServe } from "./remote-mcp/command.js";
import { loadRemoteTrust, remoteMcpUrl } from "./remote-mcp/report.js";
import { buildTrustReport, formatTrustReport } from "./trust-report.js";

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
function selectedMode(): "controlled" | "read-only" {
  const mode = flag("--mode") ?? "controlled";
  if (mode !== "controlled" && mode !== "read-only") throw new Error("Mode must be controlled or read-only.");
  return mode;
}
function dispatcherPath(mode: "controlled" | "read-only"): string {
  return flag("--dispatcher")
    ?? (mode === "controlled" ? process.env.OPSHAVEN_DISPATCHER : process.env.OPSHAVEN_READONLY_DISPATCHER)
    ?? (mode === "controlled" ? "/usr/local/bin/opshaven-dispatcher" : "/usr/local/bin/opshaven-readonly-dispatcher");
}
function optionalPort(): number | undefined {
  const raw = flag("--port");
  if (raw === undefined) return undefined;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error("Port must be an integer from 1 to 65535.");
  return value;
}

async function regularFile(path: string, ownerOnly: boolean): Promise<{ exists: boolean; safe: boolean }> {
  try {
    const stat = await fs.lstat(path);
    return { exists: true, safe: stat.isFile() && !stat.isSymbolicLink() && (!ownerOnly || (stat.mode & 0o077) === 0) };
  } catch { return { exists: false, safe: false }; }
}

async function main(): Promise<void> {
  const selected = command();
  if (selected === "help") {
    process.stdout.write("OpsHaven commands: serve, validate-config, diagnostics, verify-audit, verify-boundary, compare-capabilities, trust-report, approve-restart, approve-deploy, approve-rollback, print-mcp-config, print-remote-mcp-url\n");
    return;
  }
  if (selected === "compare-capabilities") {
    const previous = await loadCapabilityDeclaration(required("--from"));
    const current = await loadCapabilityDeclaration(flag("--to") ?? "security/capability-declaration.json");
    const comparison = compareCapabilityDeclarations(previous, current);
    process.stdout.write(process.argv.includes("--json") ? `${JSON.stringify(comparison)}\n` : formatCapabilityComparison(comparison));
    process.exitCode = comparison.authorityExpanded ? 2 : 0;
    return;
  }
  const path = configPath();
  if (!path) throw new Error("A configuration path is required.");
  const config = await loadConfig(path);
  if (selected === "serve") {
    const bindHost = flag("--bind");
    const port = optionalPort();
    const endpoint = flag("--path");
    await runRemoteServe(config, path, {
      transport: required("--transport"),
      ...(bindHost !== undefined ? { bindHost } : {}),
      ...(port !== undefined ? { port } : {}),
      ...(endpoint !== undefined ? { path: endpoint } : {}),
      unsafeAllowNonLoopback: process.argv.includes("--unsafe-allow-non-loopback"),
    });
    return;
  }
  if (selected === "validate-config") {
    const remote = await loadRemoteTrust(path, config);
    process.stdout.write(`${JSON.stringify({ ok: remote.assertions.every((item) => item.passed), version: config.version, policyVersion: config.policyVersion, resources: config.resources.size, remoteMcp: remote.summary })}\n`);
    process.exitCode = remote.assertions.every((item) => item.passed) ? 0 : 1;
    return;
  }
  if (selected === "verify-audit") {
    const result = await new AuditLog(config.audit.path).verify();
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = result.valid ? 0 : 1;
    return;
  }
  if (selected === "verify-boundary") {
    const base = await verifyBoundary(config, path, selectedMode());
    const remote = await loadRemoteTrust(path, config);
    const report = { ...base, assertions: [...base.assertions, ...remote.assertions], ok: base.ok && remote.assertions.every((item) => item.passed) };
    process.stdout.write(process.argv.includes("--json") ? `${JSON.stringify(report)}\n` : formatBoundaryReport(report));
    process.exitCode = report.ok ? 0 : 1;
    return;
  }
  if (selected === "trust-report") {
    const mode = selectedMode();
    const report = await buildTrustReport(config, path, dispatcherPath(mode), mode, flag("--from"));
    process.stdout.write(process.argv.includes("--json") ? `${JSON.stringify(report)}\n` : formatTrustReport(report));
    process.exitCode = report.ok ? 0 : 1;
    return;
  }
  if (selected === "diagnostics") {
    const hosts = [...config.resources.values()].filter((item) => item.kind === "host");
    const hostFiles = await Promise.all(hosts.map(async (host) => ({ resourceId: host.id, knownHosts: await regularFile(host.knownHostsFile, false), identity: await regularFile(host.identityFile, true) })));
    const approvals = { secret: await regularFile(config.approvals.secretFile, true), privateKey: await regularFile(config.approvals.signingPrivateKeyFile, true), publicKey: await regularFile(config.approvals.verificationPublicKeyFile, false) };
    const remote = await loadRemoteTrust(path, config);
    const ok = hostFiles.every((item) => item.knownHosts.safe && item.identity.safe) && approvals.secret.safe && approvals.privateKey.safe && approvals.publicKey.safe && remote.assertions.every((item) => item.passed);
    process.stdout.write(`${JSON.stringify({ ok, policyVersion: config.policyVersion, hosts: hostFiles, approvals, remoteMcp: remote.summary })}\n`);
    process.exitCode = ok ? 0 : 1;
    return;
  }
  if (selected === "print-mcp-config") {
    process.stdout.write(`${JSON.stringify({ mcpServers: { opshaven: { command: "opshaven-mcp", args: ["--config", path] } } }, null, 2)}\n`);
    return;
  }
  if (selected === "print-remote-mcp-url") {
    const remote = await loadRemoteTrust(path, config);
    process.stdout.write(`${JSON.stringify({ ok: true, url: remoteMcpUrl(remote.config), authentication: "oidc-bearer", credentialsIncluded: false })}\n`);
    return;
  }
  const service = new OperationService(config, undefined, path);
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
