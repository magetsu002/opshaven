import type { OpsHavenConfig } from "../config/schema.js";
import { OpsHavenError, errorMessage } from "../core/errors.js";
import type { OperationName } from "../policy/operations.js";
import type { JsonValue } from "../security/canonical.js";
import { parseDispatcherRequest, type DispatcherRequest, type DispatcherResponse } from "./protocol.js";
import { requireHost } from "./runtime.js";

export type DispatcherHandler = (
  request: DispatcherRequest,
  config: OpsHavenConfig,
  dispatcherHostId: string
) => Promise<JsonValue>;

export type DispatcherHandlers = Readonly<Partial<Record<OperationName, DispatcherHandler>>>;

function failure(requestId: string, error: unknown): DispatcherResponse {
  if (error instanceof OpsHavenError) {
    return {
      version: 1,
      requestId,
      ok: false,
      error: {
        code: error.code,
        message: error.message,
        retryable: ["SSH_TIMEOUT", "OPERATION_FAILED"].includes(error.code),
        details: error.details as { readonly [key: string]: JsonValue }
      }
    };
  }
  return {
    version: 1,
    requestId,
    ok: false,
    error: { code: "OPERATION_FAILED", message: errorMessage(error), retryable: false, details: {} }
  };
}

export class Dispatcher {
  readonly #config: OpsHavenConfig;
  readonly #handlers: DispatcherHandlers;
  readonly #hostId: string;

  public constructor(config: OpsHavenConfig, handlers: DispatcherHandlers, hostId: string) {
    requireHost(config, hostId);
    this.#config = config;
    this.#handlers = Object.freeze({ ...handlers });
    this.#hostId = hostId;
  }

  public async handle(value: unknown): Promise<DispatcherResponse> {
    let requestId = "00000000-0000-4000-8000-000000000000";
    try {
      const request = parseDispatcherRequest(value);
      requestId = request.requestId;
      const handler = this.#handlers[request.operation];
      if (handler === undefined) {
        throw new OpsHavenError("POLICY_DENIED", "Operation is not implemented by this dispatcher");
      }
      const data = await handler(request, this.#config, this.#hostId);
      return { version: 1, requestId, ok: true, data };
    } catch (error) {
      return failure(requestId, error);
    }
  }
}
