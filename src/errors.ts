export type ErrorCode =
  | "CONFIG_INVALID"
  | "UNKNOWN_OPERATION"
  | "UNKNOWN_RESOURCE"
  | "INVALID_ARGUMENTS"
  | "POLICY_DENIED"
  | "APPROVAL_REQUIRED"
  | "APPROVAL_INVALID"
  | "APPROVAL_EXPIRED"
  | "APPROVAL_REPLAYED"
  | "SSH_FAILED"
  | "SSH_HOST_KEY_FAILED"
  | "REMOTE_PROTOCOL_INVALID"
  | "REMOTE_OPERATION_FAILED"
  | "TIMEOUT"
  | "CANCELLED"
  | "OUTPUT_LIMIT"
  | "BINARY_OUTPUT"
  | "AUDIT_FAILED"
  | "INTERNAL_ERROR";

export class OpsHavenError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly retryable = false,
    readonly safeDetails?: Readonly<Record<string, unknown>>,
  ) {
    super(message);
    this.name = "OpsHavenError";
  }
}

export function asOpsHavenError(error: unknown): OpsHavenError {
  if (error instanceof OpsHavenError) return error;
  return new OpsHavenError("INTERNAL_ERROR", "The operation failed safely.", false);
}
