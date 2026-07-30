#!/usr/bin/env node
import { loadConfig } from "./config/load.js";
import {
  loadApprovalKey,
  parseApprovalRequestFile,
  signApprovalRequest
} from "./security/approval.js";
import { verifyAuditLog } from "./security/audit.js";

function usage(): never {
  process.stderr.write([
    "Usage:",
    "  opshaven audit verify --config /absolute/path/config.json",
    "  opshaven approve --config /absolute/path/config.json --request /absolute/path/request.json"
  ].join("\n") + "\n");
  process.exit(2);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] === "audit" && args[1] === "verify" && args[2] === "--config" && args[3] !== undefined && args.length === 4) {
    const config = await loadConfig(args[3]);
    const result = await verifyAuditLog(config.audit.path);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!result.valid) process.exitCode = 1;
    return;
  }
  if (
    args[0] === "approve" &&
    args[1] === "--config" &&
    args[2] !== undefined &&
    args[3] === "--request" &&
    args[4] !== undefined &&
    args.length === 5
  ) {
    const config = await loadConfig(args[2]);
    const request = await parseApprovalRequestFile(args[4]);
    const key = await loadApprovalKey(config.approvals.keyEnvironmentVariable);
    process.stdout.write(`${JSON.stringify(signApprovalRequest(request, key), null, 2)}\n`);
    return;
  }
  usage();
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "Command failed"}\n`);
  process.exitCode = 1;
});
