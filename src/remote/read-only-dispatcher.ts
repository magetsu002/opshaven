#!/usr/bin/env node
import { createHash } from "node:crypto";
import { loadVerifiedDeclarationBinding } from "../capability-declaration.js";
import { assertCapabilityAllows, loadVerifiedCapability, type VerifiedCapability } from "../capabilities.js";
import { loadConfig, type OpsHavenConfig } from "../config.js";
import { asOpsHavenError, OpsHavenError } from "../errors.js";
import { readRegularFile } from "../safe-fs.js";
import {
  createAuthenticatedResponse,
  requestReplayDirectory,
  responsePrivateKeyPath,
  verifyAuthenticatedRequest,
  type AuthenticatedResponseEnvelope,
} from "./authenticated-protocol.js";
import { assertRemoteConfinement } from "./confinement.js";
import { handleReadOnlyInspection } from "./read-only-handlers.js";
import {
  parseReadOnlyRemoteRequest,
  validateReadOnlyRemoteRequest,
  type ReadOnlyRemoteFailure,
  type ReadOnlyRemoteResponse,
  type ReadOnlyRemoteSuccess,
} from "./read-only-protocol.js";
import { FixedCommandRunner, type CommandRunner } from "./runner.js";

async function readBoundedInput(maxBytes = 65536): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    process.stdin.on("data", (chunk: Uint8Array) => {
      bytes += chunk.length;
      if (bytes > maxBytes) reject(new OpsHavenError("OUTPUT_LIMIT", "Read-only remote request exceeded its byte limit."));
      else chunks.push(chunk);
    });
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", () => reject(new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Read-only remote request could not be read.")));
  });
}

function configPath(argv: readonly string[]): string {
  if (argv.length !== 4 || argv[2] !== "--config" || !argv[3]?.startsWith("/")) throw new OpsHavenError("CONFIG_INVALID", "Read-only dispatcher requires one trusted absolute configuration path.");
  return argv[3];
}

function failure(requestId: string, startedAt: string, error: unknown): ReadOnlyRemoteFailure {
  const safe = asOpsHavenError(error);
  return { version: 1, requestId, ok: false, error: { code: safe.code, message: safe.message, retryable: safe.retryable }, evidence: { startedAt, finishedAt: new Date().toISOString(), truncated: false, redactions: 0 } };
}

function parseJsonInput(raw: string): unknown {
  try { return JSON.parse(raw) as unknown; }
  catch { throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Read-only remote request is not valid JSON."); }
}

export async function dispatchReadOnlyEnvelope(
  config: OpsHavenConfig,
  raw: string,
  runner: CommandRunner = new FixedCommandRunner(),
  originalCommand = "",
  capability?: VerifiedCapability,
): Promise<ReadOnlyRemoteResponse> {
  const startedAt = new Date().toISOString();
  let requestId = "invalid";
  try {
    if (originalCommand.trim().length > 0) throw new OpsHavenError("POLICY_DENIED", "Original SSH commands are forbidden.");
    if (raw.split(/\r?\n/).filter(Boolean).length !== 1) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Exactly one read-only request envelope is required.");
    const request = validateReadOnlyRemoteRequest(config, parseReadOnlyRemoteRequest(parseJsonInput(raw)));
    if (capability) assertCapabilityAllows(capability, request.operation, request.resourceId, request.limits);
    requestId = request.requestId;
    const data = await handleReadOnlyInspection({ config, runner }, request);
    const success: ReadOnlyRemoteSuccess = { version: 1, requestId, ok: true, data, evidence: { startedAt, finishedAt: new Date().toISOString(), truncated: data.truncated === true, redactions: typeof data.redactions === "number" ? data.redactions : 0 } };
    return success;
  } catch (error) {
    return failure(requestId, startedAt, error);
  }
}

export async function dispatchReadOnly(
  argv = process.argv,
  originalCommand = process.env.SSH_ORIGINAL_COMMAND ?? "",
): Promise<AuthenticatedResponseEnvelope | ReadOnlyRemoteFailure> {
  const startedAt = new Date().toISOString();
  if (originalCommand.trim().length > 0) return failure("invalid", startedAt, new OpsHavenError("POLICY_DENIED", "Original SSH commands are forbidden."));
  let requestId = "invalid";
  try {
    const trustedConfigPath = configPath(argv);
    const config = await loadConfig(trustedConfigPath);
    const dispatcherPath = process.argv[1] ?? "";
    await assertRemoteConfinement(config, trustedConfigPath, dispatcherPath, "read-only");
    await loadVerifiedDeclarationBinding(config, trustedConfigPath, "read-only", dispatcherPath);
    const capability = await loadVerifiedCapability(config, trustedConfigPath, "read-only", dispatcherPath);
    const requestPublicKey = await readRegularFile(config.approvals.verificationPublicKeyFile, "Request verification key", { maxBytes: 65536, code: "POLICY_DENIED" });
    const responsePrivateKey = await readRegularFile(responsePrivateKeyPath(trustedConfigPath), "Response signing key", { maxBytes: 65536, code: "POLICY_DENIED" });
    const raw = await readBoundedInput();
    if (raw.split(/\r?\n/).filter(Boolean).length !== 1) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Exactly one authenticated read-only request envelope is required.");
    const verified = await verifyAuthenticatedRequest(parseJsonInput(raw), capability, requestPublicKey, requestReplayDirectory(config));
    requestId = verified.request.requestId;
    let response: ReadOnlyRemoteResponse;
    try {
      const request = validateReadOnlyRemoteRequest(config, parseReadOnlyRemoteRequest(verified.request));
      assertCapabilityAllows(capability, request.operation, request.resourceId, request.limits);
      const data = await handleReadOnlyInspection({ config, runner: new FixedCommandRunner() }, request);
      response = { version: 1, requestId, ok: true, data, evidence: { startedAt, finishedAt: new Date().toISOString(), truncated: data.truncated === true, redactions: typeof data.redactions === "number" ? data.redactions : 0 } };
    } catch (error) {
      response = failure(requestId, startedAt, error);
    }
    return createAuthenticatedResponse(response, verified.requestHash, capability, responsePrivateKey);
  } catch (error) {
    return failure(requestId, startedAt, error);
  }
}

if (process.argv[1]?.endsWith("read-only-dispatcher.js") || process.argv[1]?.endsWith("opshaven-readonly-dispatcher")) {
  dispatchReadOnly().then((response) => process.stdout.write(`${JSON.stringify(response)}\n`)).catch(() => {
    const id = createHash("sha256").update(String(Date.now())).digest("hex").slice(0, 16);
    process.stdout.write(`${JSON.stringify({ version: 1, requestId: id, ok: false, error: { code: "INTERNAL_ERROR", message: "Read-only dispatcher failed safely.", retryable: false }, evidence: { startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), truncated: false, redactions: 0 } })}\n`);
  });
}
