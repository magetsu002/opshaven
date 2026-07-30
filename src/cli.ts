#!/usr/bin/env node
import { loadConfig } from "./config/load.js";
import { runDoctor } from "./diagnostics/doctor.js";
import {
  loadApprovalKey,
  parseApprovalRequestFile,
  signApprovalRequest
} from "./security/approval.js";
import { verifyAuditLog } from "./security/audit.js";
import { renderSudoers } from "./setup/sudoers.js";

function usage(): never {
  process.stderr.write([
    "Usage:",
    "  opshaven config validate --config /absolute/path/config.json",
    "  opshaven doctor --config /absolute/path/config.json",
    "  opshaven audit verify --config /absolute/path/config.json",
    "  opshaven approve --config /absolute/path/config.json --request /absolute/path/request.json",
    "  opshaven sudoers render --config /absolute/path/config.json"
  ].join("\n") + "\n");
  process.exit(2);
}

function configArgument(args: readonly string[], offset: number): string {
  const value = args[offset + 1];
  if (args[offset] !== "--config" || value === undefined || !value.startsWith("/")) usage();
  return value;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] === "config" && args[1] === "validate" && args.length === 4) {
    const config = await loadConfig(configArgument(args, 2));
    process.stdout.write(`${JSON.stringify({
      valid: true,
      policyVersion: config.policyVersion,
      resources: {
        hosts: config.hosts.length,
        applications: config.applications.length,
        services: config.services.length,
        containers: config.containers.length,
        deployments: config.deployments.length,
        proxies: config.proxies.length,
        probes: config.probes.length,
        databases: config.databases.length,
        monitoring: config.monitoring.length,
        backups: config.backups.length
      }
    }, null, 2)}\n`);
    return;
  }
  if (args[0] === "doctor" && args.length === 3) {
    const config = await loadConfig(configArgument(args, 1));
    const report = await runDoctor(config);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.ok) process.exitCode = 1;
    return;
  }
  if (args[0] === "audit" && args[1] === "verify" && args.length === 4) {
    const config = await loadConfig(configArgument(args, 2));
    const result = await verifyAuditLog(config.audit.path);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!result.valid) process.exitCode = 1;
    return;
  }
  if (
    args[0] === "approve" &&
    args.length === 5 &&
    args[1] === "--config" &&
    args[2]?.startsWith("/") &&
    args[3] === "--request" &&
    args[4]?.startsWith("/")
  ) {
    const config = await loadConfig(args[2]);
    const request = await parseApprovalRequestFile(args[4]);
    const key = await loadApprovalKey(config.approvals.keyEnvironmentVariable);
    process.stdout.write(`${JSON.stringify(signApprovalRequest(request, key), null, 2)}\n`);
    return;
  }
  if (args[0] === "sudoers" && args[1] === "render" && args.length === 4) {
    const config = await loadConfig(configArgument(args, 2));
    process.stdout.write(renderSudoers(config));
    return;
  }
  usage();
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "Command failed"}\n`);
  process.exitCode = 1;
});
