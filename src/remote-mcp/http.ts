import { createServer } from "node:http";
import type { McpPrincipal, McpServer } from "../mcp.js";

export const CURRENT_MCP_PROTOCOL = "2026-07-28";
const SUPPORTED_PROTOCOLS = new Set([CURRENT_MCP_PROTOCOL, "2025-11-25", "2025-06-18", "2025-03-26"]);
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

export interface HttpRequestIdentity {
  readonly authorization: string | undefined;
  readonly remoteAddress: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}
export interface PrincipalVerifier {
  verify(identity: HttpRequestIdentity): Promise<McpPrincipal>;
}
export interface StreamableHttpOptions {
  readonly mcp: McpServer;
  readonly verifier: PrincipalVerifier;
  readonly bindHost?: string;
  readonly port?: number;
  readonly path?: string;
  readonly unsafeAllowNonLoopback?: boolean;
  readonly maxBodyBytes?: number;
}
export interface StartedHttpServer {
  readonly host: string;
  readonly port: number;
  readonly path: string;
  readonly url: string;
}

export class RemoteAuthenticationError extends Error {
  constructor(readonly status: 401 | 403 = 401, message = "Remote authentication failed.") { super(message); }
}

export class RejectAllVerifier implements PrincipalVerifier {
  async verify(): Promise<McpPrincipal> { throw new RemoteAuthenticationError(401); }
}

function jsonRpcError(code: number, message: string, id: string | number | null = null): Record<string, unknown> {
  return { jsonrpc: "2.0", id, error: { code, message } };
}
function headerValue(value: string | string[] | undefined): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.length === 1) return value[0];
  return undefined;
}
function sendJson(response: any, status: number, value: unknown, extraHeaders: Record<string, string> = {}): void {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": String(Buffer.byteLength(body, "utf8")), "cache-control": "no-store", ...extraHeaders });
  response.end(body);
}
function sendEmpty(response: any, status: number, extraHeaders: Record<string, string> = {}): void {
  response.writeHead(status, { "cache-control": "no-store", ...extraHeaders });
  response.end();
}
function plain(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function requestId(value: unknown): string | number | null {
  if (!plain(value)) return null;
  return typeof value.id === "string" || typeof value.id === "number" ? value.id : null;
}
function requestMethod(value: unknown): string | undefined { return plain(value) && typeof value.method === "string" ? value.method : undefined; }
function isNotification(value: unknown): boolean { return plain(value) && value.id === undefined && typeof value.method === "string"; }
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
function decorateCurrentResponse(value: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!value || !plain(value.result)) return value;
  return { ...value, result: { resultType: "complete", ...value.result, _meta: { "io.modelcontextprotocol/serverInfo": { name: "opshaven", version: "1.0.0" } } } };
}
function modernDiscovery(id: string | number | null): Record<string, unknown> {
  return { jsonrpc: "2.0", id, result: { resultType: "complete", protocolVersion: CURRENT_MCP_PROTOCOL, capabilities: { tools: {} }, serverInfo: { name: "opshaven", version: "1.0.0" }, _meta: { "io.modelcontextprotocol/serverInfo": { name: "opshaven", version: "1.0.0" } } } };
}
function validateModernEnvelope(message: unknown, headers: Readonly<Record<string, string | string[] | undefined>>): string | undefined {
  const method = requestMethod(message);
  if (!method) return "Malformed MCP request.";
  const bodyVersion = protocolFromMessage(message);
  if (bodyVersion !== CURRENT_MCP_PROTOCOL) return "Missing or incompatible MCP request metadata.";
  if (!plain(message) || !plain(message.params) || !plain(message.params._meta)) return "Missing or incompatible MCP request metadata.";
  const meta = message.params._meta;
  if (!plain(meta["io.modelcontextprotocol/clientCapabilities"])) return "Missing or incompatible MCP request metadata.";
  const methodHeader = headerValue(headers["mcp-method"]);
  if (methodHeader !== method) return "MCP method header does not match the request.";
  const nameHeader = headerValue(headers["mcp-name"]);
  if (method === "tools/call") {
    const name = typeof message.params.name === "string" ? message.params.name : undefined;
    if (!name || nameHeader !== name) return "MCP name header does not match the request.";
  } else if (nameHeader !== undefined) return "MCP name header is not valid for this request.";
  return undefined;
}

async function readBody(request: any, maximum: number): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    let finished = false;
    const fail = (): void => { if (!finished) { finished = true; reject(new Error("BODY_LIMIT")); } };
    request.on("data", (chunk: Uint8Array) => {
      if (finished) return;
      bytes += chunk.length;
      if (bytes > maximum) { request.destroy(); fail(); return; }
      chunks.push(chunk);
    });
    request.on("end", () => { if (!finished) { finished = true; resolve(Buffer.concat(chunks).toString("utf8")); } });
    request.on("error", fail);
    request.on("aborted", fail);
  });
}

export class StreamableHttpServer {
  private server: any;
  private started: StartedHttpServer | undefined;
  constructor(private readonly options: StreamableHttpOptions) {}

  async start(): Promise<StartedHttpServer> {
    if (this.started) return this.started;
    const host = this.options.bindHost ?? "127.0.0.1";
    const port = this.options.port ?? 0;
    const endpoint = this.options.path ?? "/mcp";
    if (!endpoint.startsWith("/") || endpoint.includes("?") || endpoint.includes("#") || endpoint.length > 128) throw new Error("The MCP path is invalid.");
    if (!LOOPBACK.has(host) && this.options.unsafeAllowNonLoopback !== true) throw new Error("Non-loopback remote MCP binding requires --unsafe-allow-non-loopback.");
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("The remote MCP port is invalid.");
    const maximum = this.options.maxBodyBytes ?? 1048576;
    this.server = createServer(async (request: any, response: any) => {
      try {
        const principal = await this.options.verifier.verify({ authorization: headerValue(request.headers.authorization), remoteAddress: request.socket?.remoteAddress ?? "", headers: request.headers });
        const target = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
        if (target.pathname !== endpoint || target.search || target.hash) { sendJson(response, 404, jsonRpcError(-32601, "Not found")); return; }
        if (request.method === "GET") { response.setHeader("allow", "POST"); sendJson(response, 405, jsonRpcError(-32601, "Method not allowed")); return; }
        if (request.method !== "POST") { response.setHeader("allow", "POST"); sendJson(response, 405, jsonRpcError(-32601, "Method not allowed")); return; }
        const contentType = headerValue(request.headers["content-type"]);
        if (!contentType || contentType.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") { sendJson(response, 415, jsonRpcError(-32600, "Content-Type must be application/json")); return; }
        const accept = headerValue(request.headers.accept);
        if (!accept || !accept.toLowerCase().includes("application/json")) { sendJson(response, 406, jsonRpcError(-32600, "Accept must include application/json")); return; }
        let body: string;
        try { body = await readBody(request, maximum); }
        catch { sendJson(response, 413, jsonRpcError(-32600, "Request body exceeds the configured limit")); return; }
        let message: unknown;
        try { message = JSON.parse(body) as unknown; }
        catch { sendJson(response, 400, jsonRpcError(-32700, "Parse error")); return; }
        const method = requestMethod(message);
        const suppliedVersion = headerValue(request.headers["mcp-protocol-version"]);
        const initializeVersion = method === "initialize" && plain(message) && plain(message.params) && typeof message.params.protocolVersion === "string" ? message.params.protocolVersion : undefined;
        const protocol = suppliedVersion ?? initializeVersion;
        if (!protocol || !SUPPORTED_PROTOCOLS.has(protocol)) { sendJson(response, 400, jsonRpcError(-32022, "Unsupported MCP protocol version", requestId(message))); return; }
        if (protocol === CURRENT_MCP_PROTOCOL) {
          const invalid = validateModernEnvelope(message, request.headers);
          if (invalid) { sendJson(response, 400, jsonRpcError(-32020, invalid, requestId(message))); return; }
        }
        if (protocol === CURRENT_MCP_PROTOCOL && method === "server/discover") { sendJson(response, 200, modernDiscovery(requestId(message))); return; }
        const result = await this.options.mcp.handle(stripTransportMeta(message), principal);
        if (isNotification(message)) { sendEmpty(response, 202); return; }
        sendJson(response, 200, protocol === CURRENT_MCP_PROTOCOL ? decorateCurrentResponse(result) : result ?? jsonRpcError(-32603, "Internal error", requestId(message)));
      } catch (error) {
        if (error instanceof RemoteAuthenticationError) { sendJson(response, error.status, jsonRpcError(-32600, error.message), { "www-authenticate": "Bearer" }); return; }
        sendJson(response, 500, jsonRpcError(-32603, "Internal error"));
      }
    });
    this.server.maxHeadersCount = 64;
    this.server.requestTimeout = 30000;
    this.server.headersTimeout = 10000;
    this.server.keepAliveTimeout = 5000;
    await new Promise<void>((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(port, host, () => resolve());
    });
    const address = this.server.address();
    const actualPort = typeof address === "object" && address ? address.port : port;
    this.started = Object.freeze({ host, port: actualPort, path: endpoint, url: `http://${host.includes(":") ? `[${host}]` : host}:${actualPort}${endpoint}` });
    return this.started;
  }

  async close(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve, reject) => this.server.close((error?: Error) => error ? reject(error) : resolve()));
    this.server = undefined;
    this.started = undefined;
  }
}
