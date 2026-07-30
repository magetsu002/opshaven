#!/usr/bin/env node
import { createHash } from "node:crypto";
import { assertCapabilityAllows, loadVerifiedCapability } from "../capabilities.js";
import { loadConfig } from "../config.js";
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
import { handleInspection } from "./handlers.js";
import { handleMutation } from "./mutations.js";
import { validateRemoteRequest, type RemoteFailure, type RemoteResponse, type RemoteSuccess } from "./protocol.js";
import { FixedCommandRunner } from "./runner.js";

async function readBoundedInput(maxBytes = 65536): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    process.stdin.on("data", (chunk: Uint8Array) => {
      bytes += chunk.length;
      if (bytes > maxBytes) reject(new OpsHavenError("OUTPUT_LIMIT", "Remote request exceeded its byte limit."));
      else chunks.push(chunk);
    });
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", () => reject(new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Remote request could not be read.")));
  });
}

function configPath(argv: readonly string[]): string {
  if (argv.length !== 4 || argv[2] !== "--config" || !argv[3]?.startsWith("/")) throw new OpsHavenError("CONFIG_INVALID", "Dispatcher requires one trusted absolute configuration path.");
  return argv[3];
}

function failure(requestId: string, startedAt: string, error: unknown): RemoteFailure {
  const safe = asOpsHavenError(error);
  return {
    version: 1,
    requestId,
    ok: false,
    error: { code: safe.code, message: safe.message, retryable: safe.retryable },
    evidence: { startedAt, finishedAt: new Date().toISOString(), truncated: false, redactions: 0 },
  };
}

export async function dispatch(
  argv = process.argv,
  originalCommand = process.env.SSH_ORIGINAL_COMMAND ?? "",
): Promise<AuthenticatedResponseEnvelope | RemoteFailure> {
  const startedAt = new Date().toISOString();
  if (originalCommand.trim().length > 0) return failure("invalid", startedAt, new OpsHavenError("POLICY_DENIED", "Original SSH commands are forbidden."));
  let requestId = "invalid";
  try {
    const trustedConfigPath = configPath(argv);
    const config = await loadConfig(trustedConfigPath);
    const dispatcherPath = process.argv[1] ?? "";
    await assertRemoteConfinement(config, trustedConfigPath, dispatcherPath, "controlled");
    const capability = await loadVerifiedCapability(config, trustedConfigPath, "controlled", dispatcherPath);
    const requestPublicKey = await readRegularFile(config.approvals.verificationPublicKeyFile, "Request verification key", { maxBytes: 65536, code: "POLICY_DENIED" });
    const responsePrivateKey = await readRegularFile(responsePrivateKeyPath(trustedConfigPath), "Response signing key", { maxBytes: 65536, code: "POLICY_DENIED" });
    const raw = await readBoundedInput();
    if (raw.split(/\r?\n/).filter(Boolean).length !== 1) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Exactly one authenticated request envelope is required.");
    const verified = await verifyAuthenticatedRequest(
      JSON.parse(raw) as unknown,
      capability,
      requestPublicKey,
      requestReplayDirectory(config),
    );
    requestId = verified.request.requestId;
    let response: RemoteResponse;
    try {
      const request = validateRemoteRequest(config, verified.request);
      assertCapabilityAllows(capability, request.operation, request.resourceId, request.limits);
      const context = { config, runner: new FixedCommandRunner() };
      const data = request.operation === "restart_service" || request.operation === "deploy_commit" || request.operation === "rollback_deployment"
        ? await handleMutation(context, request)
        : await handleInspection(context, request);
      const success: RemoteSuccess = {
        version: 1,
        requestId,
        ok: true,
        data,
        evidence: {
          startedAt,
          finishedAt: new Date().toISOString(),
          truncated: data.truncated === true,
          redactions: typeof data.redactions === "number" ? data.redactions : 0,
        },
      };
      response = success;
    } catch (error) {
      response = failure(requestId, startedAt, error);
    }
    return createAuthenticatedResponse(response, verified.requestHash, capability, responsePrivateKey);
  } catch (error) {
    return failure(requestId, startedAt, error);
  }
}

if (process.argv[1]?.endsWith("dispatcher.js") || process.argv[1]?.endsWith("opshaven-dispatcher")) {
  dispatch().then((response) => process.stdout.write(`${JSON.stringify(response)}\n`)).catch(() => {
    const id = createHash("sha256").update(String(Date.now())).digest("hex").slice(0, 16);
    process.stdout.write(`${JSON.stringify({ version: 1, requestId: id, ok: false, error: { code: "INTERNAL_ERROR", message: "Dispatcher failed safely.", retryable: false }, evidence: { startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), truncated: false, redactions: 0 } })}\n`);
  });
}
