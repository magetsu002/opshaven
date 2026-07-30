import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import type { JsonValue } from "../security/canonical.js";
import type { OperationsService } from "../service/operations-service.js";
import { VERSION } from "../version.js";
import { findMcpTool, MCP_TOOLS } from "./tools.js";

type RequestId = string | number;
type JsonRpcResponse = Readonly<{
  jsonrpc: "2.0";
  id: RequestId | null;
  result?: JsonValue;
  error?: Readonly<{ code: number; message: string; data?: JsonValue }>;
}>;

const MAX_MESSAGE_BYTES = 1_048_576;
const SUPPORTED_PROTOCOLS = ["2026-07-28", "2025-11-25", "2025-06-18", "2024-11-05"] as const;

function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function response(id: RequestId, result: JsonValue): JsonRpcResponse {
  return { jsonrpc: "2.0", id, result };
}

function failure(id: RequestId | null, code: number, message: string, data?: JsonValue): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function implementation() {
  return { name: "opshaven", version: VERSION } as const;
}

export class McpStdioServer {
  readonly #service: OperationsService;
  readonly #input: Readable;
  readonly #output: Writable;

  public constructor(service: OperationsService, input: Readable, output: Writable) {
    this.#service = service;
    this.#input = input;
    this.#output = output;
  }

  #write(message: JsonRpcResponse): void {
    this.#output.write(`${JSON.stringify(message)}\n`);
  }

  async #handleRequest(id: RequestId, method: string, params: unknown): Promise<JsonRpcResponse> {
    if (method === "server/discover") {
      return response(id, {
        resultType: "complete",
        supportedVersions: SUPPORTED_PROTOCOLS,
        capabilities: { tools: { listChanged: false } },
        serverInfo: implementation(),
        instructions: "Use configured logical resource IDs only. Mutation tools require exact expiring single-use human approval."
      });
    }
    if (method === "initialize") {
      const parsed = object(params);
      if (parsed === undefined || typeof parsed.protocolVersion !== "string") {
        return failure(id, -32602, "initialize params are invalid");
      }
      const protocolVersion = (SUPPORTED_PROTOCOLS as readonly string[]).includes(parsed.protocolVersion)
        ? parsed.protocolVersion
        : SUPPORTED_PROTOCOLS[0];
      return response(id, {
        protocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo: implementation(),
        instructions: "Use configured logical resource IDs only. Mutation tools require exact human approval."
      });
    }
    if (method === "ping") return response(id, { resultType: "complete" });
    if (method === "tools/list") {
      const parsed = params === undefined ? {} : object(params);
      if (parsed === undefined || (parsed.cursor !== undefined && parsed.cursor !== null)) {
        return failure(id, -32602, "Pagination cursors are not supported");
      }
      return response(id, {
        resultType: "complete",
        tools: MCP_TOOLS,
        ttlMs: 60_000,
        cacheScope: "global"
      } as unknown as JsonValue);
    }
    if (method === "tools/call") {
      const parsed = object(params);
      if (parsed === undefined || typeof parsed.name !== "string") {
        return failure(id, -32602, "tools/call params are invalid");
      }
      const allowed = ["name", "arguments", "_meta"];
      const unknown = Object.keys(parsed).filter((key) => !allowed.includes(key));
      if (unknown.length > 0) return failure(id, -32602, "tools/call contains unsupported fields", { fields: unknown });
      const tool = findMcpTool(parsed.name);
      if (tool === undefined) return failure(id, -32602, `Unknown tool: ${parsed.name}`);
      const envelope = await this.#service.call(tool.name, parsed.arguments ?? {});
      return response(id, {
        resultType: "complete",
        content: [{ type: "text", text: JSON.stringify(envelope) }],
        structuredContent: envelope as unknown as JsonValue,
        isError: !envelope.ok
      });
    }
    return failure(id, -32601, `Method not found: ${method}`);
  }

  async #handleLine(line: string): Promise<void> {
    if (Buffer.byteLength(line, "utf8") > MAX_MESSAGE_BYTES) {
      this.#write(failure(null, -32600, "JSON-RPC message exceeds the input limit"));
      return;
    }
    let value: unknown;
    try {
      value = JSON.parse(line) as unknown;
    } catch {
      this.#write(failure(null, -32700, "Parse error"));
      return;
    }
    const request = object(value);
    if (request === undefined || request.jsonrpc !== "2.0" || typeof request.method !== "string") {
      this.#write(failure(null, -32600, "Invalid Request"));
      return;
    }
    const id = request.id;
    if (id === undefined) {
      if (["notifications/initialized", "notifications/cancelled"].includes(request.method)) return;
      return;
    }
    if (typeof id !== "string" && typeof id !== "number") {
      this.#write(failure(null, -32600, "Request id must be a string or number"));
      return;
    }
    this.#write(await this.#handleRequest(id, request.method, request.params));
  }

  public async run(): Promise<void> {
    const lines = createInterface({ input: this.#input, crlfDelay: Infinity, terminal: false });
    for await (const line of lines) {
      if (line.length === 0) continue;
      await this.#handleLine(line);
    }
  }
}
