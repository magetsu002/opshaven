export type ErrorCode =
  | "CONFIG_INVALID"
  | "RESOURCE_NOT_FOUND"
  | "POLICY_DENIED"
  | "APPROVAL_REQUIRED"
  | "APPROVAL_INVALID"
  | "APPROVAL_REPLAYED"
  | "SSH_CONNECT_FAILED"
  | "SSH_HOST_KEY_MISMATCH"
  | "SSH_TIMEOUT"
  | "REMOTE_PROTOCOL_ERROR"
  | "OUTPUT_LIMIT_EXCEEDED"
  | "BINARY_OUTPUT_REJECTED"
  | "OPERATION_FAILED"
  | "AUDIT_FAILURE";

export class OpsHavenError extends Error {
  public readonly code: ErrorCode;
  public readonly details: Readonly<Record<string, unknown>>;

  public constructor(code: ErrorCode, message: string, details: Readonly<Record<string, unknown>> = {}) {
    super(message);
    this.name = "OpsHavenError";
    this.code = code;
    this.details = details;
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown error";
}
