export type ResourceId = string;
export type HostId = ResourceId;

export type OutputBounds = Readonly<{
  maxBytes: number;
  maxLines: number;
}>;

export type ResultEnvelope<T> = Readonly<{
  ok: true;
  operation: string;
  requestId: string;
  hostId: HostId;
  observedAt: string;
  data: T;
  truncated: boolean;
}>;

export type ErrorEnvelope = Readonly<{
  ok: false;
  operation: string;
  requestId: string;
  code: string;
  message: string;
  retryable: boolean;
  details: Readonly<Record<string, unknown>>;
}>;

export type OperationEnvelope<T> = ResultEnvelope<T> | ErrorEnvelope;
