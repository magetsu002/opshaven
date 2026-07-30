import { TextDecoder } from "node:util";
import type { HostConfig } from "../config/schema.js";
import { OpsHavenError } from "../core/errors.js";
import type { ResolvedOperation } from "../policy/operations.js";
import { canonicalJson, type JsonValue } from "../security/canonical.js";
import { runProcess, type ProcessRunner } from "./process.js";

export type RemoteResponse = Readonly<{
  version: 1;
  requestId: string;
  ok: boolean;
  data?: JsonValue;
  error?: Readonly<{ code: string; message: string; retryable: boolean; details?: Record<string, JsonValue> }>;
}>;

function destination(host: HostConfig): string {
  return `${host.username}@${host.address}`;
}

function knownHostLookup(host: HostConfig): string {
  return host.port === 22 ? host.address : `[${host.address}]:${host.port}`;
}

function strictDecode(bytes: Uint8Array, context: string): string {
  if (bytes.includes(0)) throw new OpsHavenError("BINARY_OUTPUT_REJECTED", `${context} contains a NUL byte`);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new OpsHavenError("BINARY_OUTPUT_REJECTED", `${context} is not valid UTF-8`);
  }
}

function responseObject(value: unknown, context: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", `${context} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactFields(value: Record<string, unknown>, allowed: readonly string[], context: string): void {
  const unknown = Object.keys(value).filter((field) => !allowed.includes(field));
  if (unknown.length > 0) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", `${context} contains unknown fields`, { fields: unknown });
  }
}

function parseRemoteResponse(text: string, requestId: string): RemoteResponse {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Remote dispatcher returned invalid JSON");
  }
  const response = responseObject(value, "Remote dispatcher response");
  if (response.version !== 1 || response.requestId !== requestId || typeof response.ok !== "boolean") {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Remote dispatcher response header failed strict validation");
  }
  if (response.ok) {
    exactFields(response, ["version", "requestId", "ok", "data"], "Successful remote response");
    if (!("data" in response)) {
      throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Successful remote response is missing data");
    }
    return response as RemoteResponse;
  }
  exactFields(response, ["version", "requestId", "ok", "error"], "Failed remote response");
  const error = responseObject(response.error, "Remote error");
  exactFields(error, ["code", "message", "retryable", "details"], "Remote error");
  if (
    typeof error.code !== "string" ||
    error.code.length === 0 ||
    typeof error.message !== "string" ||
    typeof error.retryable !== "boolean"
  ) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Remote error contains invalid fields");
  }
  if (error.details !== undefined) responseObject(error.details, "Remote error details");
  return response as RemoteResponse;
}

export class RestrictedSshTransport {
  readonly #runner: ProcessRunner;

  public constructor(runner: ProcessRunner = runProcess) {
    this.#runner = runner;
  }

  public async verifyPinnedHostKey(host: HostConfig): Promise<void> {
    const lookup = await this.#runner({
      executable: "/usr/bin/ssh-keygen",
      args: ["-F", knownHostLookup(host), "-f", host.knownHostsFile],
      timeoutMs: 5_000,
      output: { maxBytes: 32_768, maxLines: 100 }
    });
    if (lookup.exitCode !== 0 || lookup.stdout.byteLength === 0) {
      throw new OpsHavenError("SSH_HOST_KEY_MISMATCH", "Pinned host is absent from the dedicated known_hosts file");
    }
    const fingerprint = await this.#runner({
      executable: "/usr/bin/ssh-keygen",
      args: ["-lf", "-", "-E", "sha256"],
      stdin: lookup.stdout,
      timeoutMs: 5_000,
      output: { maxBytes: 32_768, maxLines: 100 }
    });
    const text = strictDecode(fingerprint.stdout, "ssh-keygen output");
    if (fingerprint.exitCode !== 0 || !text.includes(host.hostKeySha256)) {
      throw new OpsHavenError("SSH_HOST_KEY_MISMATCH", "Pinned SSH host-key fingerprint does not match configuration");
    }
  }

  public async execute(host: HostConfig, operation: ResolvedOperation): Promise<RemoteResponse> {
    await this.verifyPinnedHostKey(host);
    const request = canonicalJson({
      version: 1,
      requestId: operation.requestId,
      operation: operation.operation,
      target: operation.target,
      args: operation.args,
      expectedState: operation.expectedState,
      dryRun: operation.dryRun,
      limits: { timeoutMs: operation.timeoutMs, ...operation.output }
    });
    const result = await this.#runner({
      executable: "/usr/bin/ssh",
      args: [
        "-T",
        "-p",
        String(host.port),
        "-i",
        host.identityFile,
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "RequestTTY=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        `UserKnownHostsFile=${host.knownHostsFile}`,
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "--",
        destination(host),
        host.dispatcherCommand
      ],
      stdin: Buffer.from(`${request}\n`, "utf8"),
      timeoutMs: operation.timeoutMs,
      output: operation.output
    });
    const stderr = strictDecode(result.stderr, "SSH stderr").trim();
    if (result.exitCode !== 0) {
      throw new OpsHavenError("SSH_CONNECT_FAILED", "Restricted SSH operation failed", {
        exitCode: result.exitCode,
        stderr: stderr.slice(0, 512)
      });
    }
    const stdout = strictDecode(result.stdout, "SSH stdout").trim();
    if (stdout.includes("\n")) {
      throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Dispatcher emitted more than one response line");
    }
    return parseRemoteResponse(stdout, operation.requestId);
  }
}
