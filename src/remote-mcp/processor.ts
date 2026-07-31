import type { McpPrincipal, McpServer } from "../mcp.js";
import { validateJsonComplexity } from "./limits.js";
import { RemoteSessionError, type RemoteSessionManager, type SessionLease } from "./sessions.js";

export const CURRENT_MCP_PROTOCOL = "2026-07-28";
const SUPPORTED_PROTOCOLS = new Set([CURRENT_MCP_PROTOCOL, "2025-11-25", "2025-06-18", "2025-03-26"]);

export interface ProcessorLimits {
  readonly maximumJsonDepth: number;
  readonly maximumJsonNodes: number;
  readonly maximumResponseBytes: number;
}
export interface RemoteHttpResult {
  readonly status: number;
  readonly body?: string;
  readonly headers: Readonly<Record<string, string>>;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (typeof value === "string" && value.length <= 4096 && !value.includes(",") && !/[\r\n]/.test(value)) return value;
  if (Array.isArray(value) && value.length === 1) return headerValue(value[0]);
  return undefined;
}
function plain(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function requestId(value: unknown): string | number | null {
  if (!plain(value)) return null;
  return typeof value.id === "string" || typeof value.id === "number" ? value.id : null;
}
function requestMethod(value: unknown): string | undefined { return plain(value) && typeof value.method === "string" ? value.method : undefined; }
function notification(value: unknown): boolean { return plain(value) && value.id === undefined && typeof value.method === "string"; }
function rpcError(code: number, message: string, id: string | number | null = null): Record<string, unknown> { return { jsonrpc: "2.0", id, error: { code, message } }; }
function protocolFromMessage(value: unknown): string | undefined {
  if (!plain(value) || !plain(value.params) || !plain(value.params._meta)) return undefined;
  const version = value.params._meta["io.modelcontextprotocol/protocolVersion"];
  return typeof version === "string" ? version : undefined;
}
function stripTransportMeta(value: unknown): unknown {
  if (!plain(value) || !plain(value.params) || value.params._meta === undefined) return value;
  const params = { ...value.params };
  delete params._meta;
  return { ...value, params };
}
function validateModernEnvelope(message: unknown, headers: Readonly<Record<string, string | string[] | undefined>>): string | undefined {
  const method = requestMethod(message);
  if (!method) return "Malformed MCP request.";
  if (protocolFromMessage(message) !== CURRENT_MCP_PROTOCOL) return "Missing or incompatible MCP request metadata.";
  if (!plain(message) || !plain(message.params) || !plain(message.params._meta) || !plain(message.params._meta["io.modelcontextprotocol/clientCapabilities"])) return "Missing or incompatible MCP request metadata.";
  if (headerValue(headers["mcp-method"]) !== method) return "MCP method header does not match the request.";
  const nameHeader = headerValue(headers["mcp-name"]);
  if (method === "tools/call") {
    const name = typeof message.params.name === "string" ? message.params.name : undefined;
    if (!name || nameHeader !== name) return "MCP name header does not match the request.";
  } else if (nameHeader !== undefined) return "MCP name header is not valid for this request.";
  return undefined;
}
function protocolForRequest(message: unknown, headers: Readonly<Record<string, string | string[] | undefined>>): string | undefined {
  const supplied = headerValue(headers["mcp-protocol-version"]);
  const method = requestMethod(message);
  const initialized = method === "initialize" && plain(message) && plain(message.params) && typeof message.params.protocolVersion === "string" ? message.params.protocolVersion : undefined;
  return supplied ?? initialized;
}
function modernDiscovery(id: string | number | null): Record<string, unknown> {
  return { jsonrpc: "2.0", id, result: { resultType: "complete", protocolVersion: CURRENT_MCP_PROTOCOL, capabilities: { tools: {} }, serverInfo: { name: "opshaven", version: "1.0.0" }, _meta: { "io.modelcontextprotocol/serverInfo": { name: "opshaven", version: "1.0.0" } } } };
}
function decorateCurrentResponse(value: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!value || !plain(value.result)) return value;
  return { ...value, result: { resultType: "complete", ...value.result, _meta: { "io.modelcontextprotocol/serverInfo": { name: "opshaven", version: "1.0.0" } } } };
}
function result(status: number, value: unknown | undefined, limits: ProcessorLimits, headers: Record<string, string> = {}): RemoteHttpResult {
  if (value === undefined) return Object.freeze({ status, headers: Object.freeze({ ...headers }) });
  let body = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(body, "utf8") > limits.maximumResponseBytes) {
    body = `${JSON.stringify(rpcError(-32040, "Remote MCP response exceeds the configured limit"))}\n`;
    return Object.freeze({ status: 413, body, headers: Object.freeze({ ...headers }) });
  }
  return Object.freeze({ status, body, headers: Object.freeze({ ...headers }) });
}

export class RemoteMcpProcessor {
  constructor(private readonly mcp: McpServer, private readonly limits: ProcessorLimits, private readonly sessions?: RemoteSessionManager) {}

  delete(headers: Readonly<Record<string, string | string[] | undefined>>, principal: McpPrincipal): RemoteHttpResult {
    const protocol = headerValue(headers["mcp-protocol-version"]);
    const session = headerValue(headers["mcp-session-id"]);
    if (!this.sessions || !protocol || protocol === CURRENT_MCP_PROTOCOL || !SUPPORTED_PROTOCOLS.has(protocol) || !session) throw new RemoteSessionError(400);
    this.sessions.delete(session, principal);
    return result(204, undefined, this.limits);
  }

  async post(body: string, headers: Readonly<Record<string, string | string[] | undefined>>, initialPrincipal: McpPrincipal, signal?: AbortSignal): Promise<RemoteHttpResult> {
    let message: unknown;
    try { message = JSON.parse(body) as unknown; }
    catch { return result(400, rpcError(-32700, "Parse error"), this.limits); }
    validateJsonComplexity(message, this.limits.maximumJsonDepth, this.limits.maximumJsonNodes);
    const method = requestMethod(message);
    const protocol = protocolForRequest(message, headers);
    if (!protocol || !SUPPORTED_PROTOCOLS.has(protocol)) return result(400, rpcError(-32022, "Unsupported MCP protocol version", requestId(message)), this.limits);
    const sessionHeader = headerValue(headers["mcp-session-id"]);
    let principal = initialPrincipal;
    let lease: SessionLease | undefined;
    const responseHeaders: Record<string, string> = {};
    try {
      if (protocol === CURRENT_MCP_PROTOCOL) {
        if (sessionHeader !== undefined) throw new RemoteSessionError(400);
        const invalid = validateModernEnvelope(message, headers);
        if (invalid) return result(400, rpcError(-32020, invalid, requestId(message)), this.limits);
      } else if (this.sessions) {
        if (method === "initialize") {
          if (sessionHeader !== undefined) throw new RemoteSessionError(400);
          const created = this.sessions.create(principal, protocol);
          principal = Object.freeze({ ...principal, sessionId: created });
          responseHeaders["mcp-session-id"] = created;
        } else {
          if (!sessionHeader) throw new RemoteSessionError(400);
          lease = this.sessions.acquire(sessionHeader, principal, protocol, requestId(message));
          principal = lease.principal;
        }
      }
      if (protocol === CURRENT_MCP_PROTOCOL && method === "server/discover") return result(200, modernDiscovery(requestId(message)), this.limits);
      const handled = await this.mcp.handle(stripTransportMeta(message), principal, signal);
      if (notification(message)) return result(202, undefined, this.limits, responseHeaders);
      const response = protocol === CURRENT_MCP_PROTOCOL ? decorateCurrentResponse(handled) : handled ?? rpcError(-32603, "Internal error", requestId(message));
      return result(200, response, this.limits, responseHeaders);
    } finally { lease?.release(); }
  }

  close(): void { this.sessions?.close(); }
}
