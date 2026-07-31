export interface HttpBoundaryPolicy {
  readonly allowedOrigins: readonly string[];
  readonly allowedHosts: readonly string[];
  readonly trustedProxies: readonly string[];
}

export class RemoteBoundaryError extends Error {
  constructor(readonly status: 400 | 403, message = "Remote HTTP boundary rejected the request.") { super(message); }
}

function single(value: string | string[] | undefined, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || value.includes(",") || /[\r\n]/.test(value)) throw new RemoteBoundaryError(400, `${label} is ambiguous.`);
  return value;
}
function address(value: string): string { return value.startsWith("::ffff:") ? value.slice(7) : value; }
function exactHost(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^(?:localhost|\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::[0-9]{1,5})?$/.test(normalized)) throw new RemoteBoundaryError(400, "Host is malformed.");
  return normalized;
}
function exactOrigin(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); }
  catch { throw new RemoteBoundaryError(403, "Origin is not allowed."); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) throw new RemoteBoundaryError(403, "Origin is not allowed.");
  return parsed.origin;
}
function forwardedPresent(headers: Readonly<Record<string, string | string[] | undefined>>): boolean {
  return ["forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port"].some((name) => headers[name] !== undefined);
}

export function validateHttpBoundary(
  policy: HttpBoundaryPolicy,
  remoteAddress: string,
  headers: Readonly<Record<string, string | string[] | undefined>>,
): { readonly host: string; readonly origin?: string; readonly proxied: boolean } {
  const trustedProxy = policy.trustedProxies.includes(address(remoteAddress));
  const forwarded = forwardedPresent(headers);
  if (forwarded && !trustedProxy) throw new RemoteBoundaryError(403, "Forwarded headers are not trusted from this address.");
  if (headers.forwarded !== undefined) throw new RemoteBoundaryError(400, "The Forwarded header is unsupported; use the reviewed X-Forwarded fields.");
  const directHost = single(headers.host, "Host");
  if (!directHost) throw new RemoteBoundaryError(400, "Host is required.");
  let effectiveHost = exactHost(directHost);
  if (trustedProxy) {
    const forwardedFor = single(headers["x-forwarded-for"], "X-Forwarded-For");
    const forwardedHost = single(headers["x-forwarded-host"], "X-Forwarded-Host");
    const forwardedProto = single(headers["x-forwarded-proto"], "X-Forwarded-Proto");
    const forwardedPort = single(headers["x-forwarded-port"], "X-Forwarded-Port");
    if (!forwardedFor || !forwardedHost || forwardedProto !== "https" || forwardedPort !== undefined) throw new RemoteBoundaryError(400, "Trusted proxy headers are incomplete or ambiguous.");
    if (!/^[0-9A-Fa-f:.]{2,64}$/.test(forwardedFor)) throw new RemoteBoundaryError(400, "Forwarded client address is malformed.");
    effectiveHost = exactHost(forwardedHost);
  }
  if (!policy.allowedHosts.map((host) => host.toLowerCase()).includes(effectiveHost)) throw new RemoteBoundaryError(403, "Host is not allowed.");
  const rawOrigin = single(headers.origin, "Origin");
  const origin = rawOrigin === undefined ? undefined : exactOrigin(rawOrigin);
  if (origin !== undefined && !policy.allowedOrigins.includes(origin)) throw new RemoteBoundaryError(403, "Origin is not allowed.");
  return Object.freeze({ host: effectiveHost, ...(origin !== undefined ? { origin } : {}), proxied: trustedProxy });
}
