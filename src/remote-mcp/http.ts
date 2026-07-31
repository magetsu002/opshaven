import { createServer } from "node:http";
import type { McpPrincipal, McpServer } from "../mcp.js";
import { RemoteBoundaryError, validateHttpBoundary, type HttpBoundaryPolicy } from "./boundary.js";
import { RemoteAdmissionController, RemoteLimitError, validateHeaderLimits, withRemoteTimeout, type AdmissionLease } from "./limits.js";
import { CURRENT_MCP_PROTOCOL, RemoteMcpProcessor, type ProcessorLimits, type RemoteHttpResult } from "./processor.js";
import { RemoteSessionError, type RemoteSessionManager } from "./sessions.js";

export { CURRENT_MCP_PROTOCOL };
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

export interface HttpRequestIdentity {
  readonly authorization: string | undefined;
  readonly remoteAddress: string;
  readonly requestTarget: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}
export interface PrincipalVerifier { verify(identity: HttpRequestIdentity): Promise<McpPrincipal> }
export interface HttpResourceLimits extends ProcessorLimits {
  readonly maximumBodyBytes: number;
  readonly maximumHeaderBytes: number;
  readonly maximumHeaders: number;
  readonly timeoutMs: number;
  readonly maximumConnections: number;
}
export interface StreamableHttpOptions {
  readonly mcp: McpServer;
  readonly verifier: PrincipalVerifier;
  readonly boundary?: HttpBoundaryPolicy;
  readonly sessionManager?: RemoteSessionManager;
  readonly admission?: RemoteAdmissionController;
  readonly limits?: HttpResourceLimits;
  readonly bindHost?: string;
  readonly port?: number;
  readonly path?: string;
  readonly unsafeAllowNonLoopback?: boolean;
}
export interface StartedHttpServer { readonly host: string; readonly port: number; readonly path: string; readonly url: string }

export class RemoteAuthenticationError extends Error {
  constructor(readonly status: 401 | 403 = 401, message = "Remote authentication failed.") { super(message); }
}
export class RejectAllVerifier implements PrincipalVerifier {
  async verify(): Promise<McpPrincipal> { throw new RemoteAuthenticationError(401); }
}

const DEFAULT_LIMITS: HttpResourceLimits = Object.freeze({
  maximumBodyBytes: 1048576,
  maximumHeaderBytes: 16384,
  maximumHeaders: 64,
  maximumJsonDepth: 16,
  maximumJsonNodes: 4096,
  maximumResponseBytes: 1048576,
  timeoutMs: 30000,
  maximumConnections: 64,
});
function headerValue(value: string | string[] | undefined): string | undefined {
  if (typeof value === "string" && value.length <= 16384 && !value.includes(",") && !/[\r\n]/.test(value)) return value;
  if (Array.isArray(value) && value.length === 1) return headerValue(value[0]);
  return undefined;
}
function rpcError(code: number, message: string): string { return `${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code, message } })}\n`; }
function sendResult(response: any, result: RemoteHttpResult): void {
  const base = { "cache-control": "no-store", "x-content-type-options": "nosniff", ...result.headers };
  if (result.body === undefined) { response.writeHead(result.status, base); response.end(); return; }
  response.writeHead(result.status, { ...base, "content-type": "application/json; charset=utf-8", "content-length": String(Buffer.byteLength(result.body, "utf8")) });
  response.end(result.body);
}
function sendError(response: any, status: number, code: number, message: string, headers: Record<string, string> = {}): void {
  const body = rpcError(code, message);
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": String(Buffer.byteLength(body, "utf8")), "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers });
  response.end(body);
}
async function readBody(request: any, maximum: number, signal: AbortSignal): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    let finished = false;
    const cleanup = (): void => signal.removeEventListener("abort", fail);
    const fail = (): void => { if (!finished) { finished = true; cleanup(); reject(new RemoteLimitError(signal.aborted ? 408 : 413)); } };
    signal.addEventListener("abort", fail, { once: true });
    request.on("data", (chunk: Uint8Array) => {
      if (finished) return;
      bytes += chunk.length;
      if (bytes > maximum) {
        finished = true;
        cleanup();
        request.resume();
        reject(new RemoteLimitError(413, "Remote MCP request body exceeds the configured limit."));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => { if (!finished) { finished = true; cleanup(); resolve(Buffer.concat(chunks).toString("utf8")); } });
    request.on("error", fail);
    request.on("aborted", fail);
  });
}

export class StreamableHttpServer {
  private server: any;
  private started: StartedHttpServer | undefined;
  private readonly limits: HttpResourceLimits;
  private readonly processor: RemoteMcpProcessor;
  constructor(private readonly options: StreamableHttpOptions) {
    this.limits = options.limits ?? DEFAULT_LIMITS;
    this.processor = new RemoteMcpProcessor(options.mcp, this.limits, options.sessionManager);
  }

  async start(): Promise<StartedHttpServer> {
    if (this.started) return this.started;
    const host = this.options.bindHost ?? "127.0.0.1";
    const port = this.options.port ?? 0;
    const endpoint = this.options.path ?? "/mcp";
    if (!endpoint.startsWith("/") || endpoint.includes("?") || endpoint.includes("#") || endpoint.length > 128) throw new Error("The MCP path is invalid.");
    if (!LOOPBACK.has(host) && this.options.unsafeAllowNonLoopback !== true) throw new Error("Non-loopback remote MCP binding requires --unsafe-allow-non-loopback.");
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("The remote MCP port is invalid.");
    this.server = createServer(async (request: any, response: any) => {
      let admission: AdmissionLease | undefined;
      try {
        validateHeaderLimits(request.headers, this.limits.maximumHeaders, this.limits.maximumHeaderBytes);
        const identity = { authorization: headerValue(request.headers.authorization), remoteAddress: request.socket?.remoteAddress ?? "", requestTarget: request.url ?? "/", headers: request.headers };
        const principal = await this.options.verifier.verify(identity);
        admission = await this.options.admission?.acquire(principal);
        if (this.options.boundary) validateHttpBoundary(this.options.boundary, identity.remoteAddress, request.headers);
        const target = new URL(identity.requestTarget, `http://${request.headers.host ?? "localhost"}`);
        if (target.pathname !== endpoint || target.search || target.hash) { sendError(response, 404, -32601, "Not found"); return; }
        if (request.method === "DELETE") { sendResult(response, this.processor.delete(request.headers, principal)); return; }
        if (request.method !== "POST") { response.setHeader("allow", "POST, DELETE"); sendError(response, 405, -32601, "Method not allowed"); return; }
        const contentType = headerValue(request.headers["content-type"]);
        if (!contentType || contentType.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") { sendError(response, 415, -32600, "Content-Type must be application/json"); return; }
        const accept = headerValue(request.headers.accept);
        if (!accept || !accept.toLowerCase().includes("application/json")) { sendError(response, 406, -32600, "Accept must include application/json"); return; }
        const disconnected = new AbortController();
        request.once?.("aborted", () => disconnected.abort());
        const result = await withRemoteTimeout(async (signal) => {
          const body = await readBody(request, this.limits.maximumBodyBytes, signal);
          return await this.processor.post(body, request.headers, principal, signal);
        }, this.limits.timeoutMs, disconnected.signal);
        sendResult(response, result);
      } catch (error) {
        if (error instanceof RemoteAuthenticationError) { sendError(response, error.status, -32600, error.message, { "www-authenticate": "Bearer" }); return; }
        if (error instanceof RemoteBoundaryError) { sendError(response, error.status, -32600, error.message); return; }
        if (error instanceof RemoteSessionError) { sendError(response, error.status, -32030, error.message); return; }
        if (error instanceof RemoteLimitError) { sendError(response, error.status, -32040, error.message); return; }
        sendError(response, 500, -32603, "Internal error");
      } finally { admission?.release(); }
    });
    this.server.maxHeadersCount = this.limits.maximumHeaders;
    this.server.maxConnections = this.limits.maximumConnections;
    this.server.requestTimeout = this.limits.timeoutMs;
    this.server.headersTimeout = Math.min(this.limits.timeoutMs, 10000);
    this.server.keepAliveTimeout = Math.min(this.limits.timeoutMs, 5000);
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
    this.options.admission?.close();
    this.processor.close();
    if (!this.server) return;
    await new Promise<void>((resolve, reject) => this.server.close((error?: Error) => error ? reject(error) : resolve()));
    this.server = undefined;
    this.started = undefined;
  }
}
