import { randomUUID } from "node:crypto";
import type { OpsHavenConfig } from "../config/schema.js";
import { OpsHavenError, type ErrorCode, errorMessage } from "../core/errors.js";
import type { OperationEnvelope } from "../core/types.js";
import { resolveOperation, type OperationName, type ResolvedOperation } from "../policy/operations.js";
import {
  ApprovalVerifier,
  createApprovalRequest,
  loadApprovalKey,
  type ApprovalRequest
} from "../security/approval.js";
import { AuditLog, type AuditEvent, type AuditOutcome } from "../security/audit.js";
import { canonicalJson, sha256, type JsonValue } from "../security/canonical.js";
import { redactJson, redactText } from "../security/redaction.js";
import { RestrictedSshTransport, type RemoteResponse } from "../transport/ssh.js";

export type OperationTransport = Readonly<{
  execute(host: OpsHavenConfig["hosts"][number], operation: ResolvedOperation): Promise<RemoteResponse>;
}>;

export type OperationsServiceDependencies = Readonly<{
  transport?: OperationTransport;
  audit?: AuditLog;
  loadKey?: (environmentVariable: string) => Promise<Uint8Array>;
  clock?: () => Date;
}>;

type JsonObject = { readonly [key: string]: JsonValue };

function retryable(code: string): boolean {
  return ["SSH_CONNECT_FAILED", "SSH_TIMEOUT", "OPERATION_FAILED"].includes(code);
}

function jsonValue(value: unknown): JsonValue {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) return null;
  return JSON.parse(serialized) as JsonValue;
}

function inputAndApproval(value: unknown): Readonly<{ input: unknown; approval: unknown }> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { input: value, approval: undefined };
  const record = value as Record<string, unknown>;
  const { approval, ...input } = record;
  return { input, approval };
}

function errorEnvelope(
  operation: string,
  requestId: string,
  code: string,
  message: string,
  details: JsonObject = {},
  isRetryable = retryable(code)
): OperationEnvelope<JsonValue> {
  return { ok: false, operation, requestId, code, message, retryable: isRetryable, details };
}

export class OperationsService {
  readonly #config: OpsHavenConfig;
  readonly #transport: OperationTransport;
  readonly #audit: AuditLog;
  readonly #loadKey: (environmentVariable: string) => Promise<Uint8Array>;
  readonly #clock: () => Date;

  public constructor(config: OpsHavenConfig, dependencies: OperationsServiceDependencies = {}) {
    this.#config = config;
    this.#transport = dependencies.transport ?? new RestrictedSshTransport();
    this.#audit = dependencies.audit ?? new AuditLog(config.audit.path);
    this.#loadKey = dependencies.loadKey ?? loadApprovalKey;
    this.#clock = dependencies.clock ?? (() => new Date());
  }

  async #appendAudit(
    operation: Pick<ResolvedOperation, "requestId" | "operation" | "hostId" | "target">,
    outcome: AuditOutcome,
    evidence: JsonValue,
    details: JsonObject = {}
  ): Promise<void> {
    const event: AuditEvent = {
      requestId: operation.requestId,
      operation: operation.operation,
      hostId: operation.hostId,
      target: operation.target,
      outcome,
      actor: "mcp",
      evidenceDigest: sha256(canonicalJson(evidence)),
      ...(Object.keys(details).length === 0 ? {} : { details })
    };
    await this.#audit.append(event);
  }

  async #approvalRequired(operation: ResolvedOperation): Promise<OperationEnvelope<JsonValue>> {
    const approvalRequest: ApprovalRequest = createApprovalRequest(
      operation,
      this.#config.approvals.ttlSeconds,
      this.#clock
    );
    const details = redactJson({ approvalRequest } as unknown as JsonValue, this.#config.secrets) as JsonObject;
    await this.#appendAudit(operation, "denied", details, {
      reason: "approval-required",
      approvalDigest: approvalRequest.digest,
      expiresAt: approvalRequest.subject.expiresAt
    });
    return errorEnvelope(
      operation.operation,
      operation.requestId,
      "APPROVAL_REQUIRED",
      "A human approval token bound to this exact operation is required",
      details,
      false
    );
  }

  public async call(operationName: OperationName, value: unknown): Promise<OperationEnvelope<JsonValue>> {
    const separated = inputAndApproval(value);
    let operation: ResolvedOperation;
    try {
      operation = resolveOperation(this.#config, operationName, separated.input);
    } catch (error) {
      const requestId = randomUUID();
      const code = error instanceof OpsHavenError ? error.code : "POLICY_DENIED";
      const message = redactText(errorMessage(error), this.#config.secrets);
      const details = redactJson(
        jsonValue(error instanceof OpsHavenError ? error.details : {}) as JsonValue,
        this.#config.secrets
      ) as JsonObject;
      try {
        await this.#appendAudit(
          { requestId, operation: operationName, hostId: "local", target: "unresolved" },
          "denied",
          details,
          { code }
        );
      } catch (auditError) {
        return errorEnvelope(operationName, requestId, "AUDIT_FAILURE", errorMessage(auditError), {}, false);
      }
      return errorEnvelope(operationName, requestId, code, message, details, retryable(code));
    }

    try {
      if (operation.requiresApproval) {
        if (separated.approval === undefined) return await this.#approvalRequired(operation);
        const key = await this.#loadKey(this.#config.approvals.keyEnvironmentVariable);
        const verifier = new ApprovalVerifier(this.#config.approvals.stateDirectory, key, this.#clock);
        const token = await verifier.verifyAndConsume(operation, separated.approval);
        await this.#appendAudit(operation, "allowed", { digest: token.digest }, { approvalDigest: token.digest });
      } else {
        if (separated.approval !== undefined) {
          throw new OpsHavenError("APPROVAL_INVALID", "Approval must not be supplied for this operation");
        }
        await this.#appendAudit(operation, operation.dryRun ? "dry-run" : "allowed", {
          operation: operation.operation,
          target: operation.target,
          dryRun: operation.dryRun
        });
      }
    } catch (error) {
      const code = error instanceof OpsHavenError ? error.code : "AUDIT_FAILURE";
      const message = redactText(errorMessage(error), this.#config.secrets);
      const details = redactJson(
        jsonValue(error instanceof OpsHavenError ? error.details : {}) as JsonValue,
        this.#config.secrets
      ) as JsonObject;
      return errorEnvelope(operation.operation, operation.requestId, code, message, details, retryable(code));
    }

    const host = this.#config.hosts.find((item) => item.id === operation.hostId);
    if (host === undefined) {
      return errorEnvelope(operation.operation, operation.requestId, "CONFIG_INVALID", "Resolved host is unavailable", {}, false);
    }

    try {
      const remote = await this.#transport.execute(host, operation);
      if (!remote.ok) {
        const remoteError = remote.error;
        const code = remoteError?.code ?? "OPERATION_FAILED";
        const message = redactText(remoteError?.message ?? "Remote operation failed", this.#config.secrets);
        const details = redactJson(jsonValue(remoteError?.details ?? {}) as JsonValue, this.#config.secrets) as JsonObject;
        await this.#appendAudit(operation, "failed", { code, message, details });
        return errorEnvelope(operation.operation, operation.requestId, code, message, details, remoteError?.retryable ?? retryable(code));
      }
      const data = redactJson(remote.data ?? null, this.#config.secrets);
      const observedAt = this.#clock().toISOString();
      await this.#appendAudit(operation, operation.dryRun ? "dry-run" : "succeeded", data);
      return {
        ok: true,
        operation: operation.operation,
        requestId: operation.requestId,
        hostId: operation.hostId,
        observedAt,
        data,
        truncated: false
      };
    } catch (error) {
      const code: ErrorCode = error instanceof OpsHavenError ? error.code : "OPERATION_FAILED";
      const message = redactText(errorMessage(error), this.#config.secrets);
      const details = redactJson(
        jsonValue(error instanceof OpsHavenError ? error.details : {}) as JsonValue,
        this.#config.secrets
      ) as JsonObject;
      try {
        await this.#appendAudit(operation, "failed", { code, message, details });
      } catch (auditError) {
        return errorEnvelope(
          operation.operation,
          operation.requestId,
          "AUDIT_FAILURE",
          redactText(errorMessage(auditError), this.#config.secrets),
          { operationMayHaveCompleted: operation.kind === "mutation" },
          false
        );
      }
      return errorEnvelope(operation.operation, operation.requestId, code, message, details, retryable(code));
    }
  }
}
