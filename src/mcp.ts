import type { OperationService, ResultEnvelope } from "./operations.js";

interface JsonRpcRequest { jsonrpc: "2.0"; id?: string | number | null; method: string; params?: unknown }
export interface ToolDefinition { name: string; description: string; inputSchema: Record<string, unknown> }
export interface ToolExecutor { execute(operation: string, args: unknown, approvalToken?: string, actor?: string, signal?: AbortSignal): Promise<ResultEnvelope> }
export interface McpPrincipal {
  readonly id: string;
  readonly transport: "stdio" | "streamable-http";
  readonly profileId?: string;
  readonly sessionId?: string;
  readonly allowedTools?: ReadonlySet<string>;
  readonly allowedResources?: ReadonlySet<string>;
}

export const STDIO_PRINCIPAL: McpPrincipal = Object.freeze({ id: "mcp-client", transport: "stdio" });

const resource = { type: "string", pattern: "^[a-z][a-z0-9._-]{0,63}$", description: "Configured logical resource ID." };
const dryRun = { type: "boolean", default: false };
const approval = { type: "string", minLength: 32, description: "Expiring single-use human approval token." };
function schema(properties: Record<string, unknown>, required: string[]): Record<string, unknown> { return { type: "object", additionalProperties: false, properties, required }; }
const TOOLS: readonly ToolDefinition[] = [
  { name: "get_host_summary", description: "Return a bounded safe host summary.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_deployed_commit", description: "Return the exact deployed Git commit and dirty-state evidence.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_service_status", description: "Return structured status for a configured system service.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_container_status", description: "Return structured status for a configured container.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_runtime_config_status", description: "Report configured environment-key presence without returning values.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_reverse_proxy_summary", description: "Return safe configured reverse-proxy metadata and service status.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_firewall_summary", description: "Return a bounded redacted firewall summary.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "run_health_probe", description: "Run one configured credential-free health probe.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_redacted_logs", description: "Return bounded doubly-redacted logs for a configured service or container.", inputSchema: schema({ resourceId: resource, lines: { type: "integer", minimum: 1, maximum: 500, default: 100 }, sinceMinutes: { type: "integer", minimum: 1, maximum: 1440, default: 60 } }, ["resourceId"]) },
  { name: "get_monitoring_status", description: "Return configured monitoring service and probe evidence.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_backup_status", description: "Return safe structured backup freshness evidence.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "get_restore_readiness", description: "Return restore-test readiness evidence and migration warning.", inputSchema: schema({ resourceId: resource }, ["resourceId"]) },
  { name: "restart_service", description: "Dry-run or restart one configured service with exact human approval.", inputSchema: schema({ resourceId: resource, dryRun, approvalToken: approval }, ["resourceId", "dryRun"]) },
  { name: "deploy_commit", description: "Dry-run or deploy one exact allowlisted Git commit using configured trusted steps.", inputSchema: schema({ resourceId: resource, commit: { type: "string", pattern: "^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$" }, expectedCurrentCommit: { type: "string", pattern: "^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$" }, dryRun, approvalToken: approval }, ["resourceId", "commit", "dryRun"]) },
  { name: "rollback_deployment", description: "Dry-run or activate a known recorded release with exact human approval.", inputSchema: schema({ resourceId: resource, releaseId: { type: "string", pattern: "^[A-Za-z0-9._-]{1,128}$" }, dryRun, approvalToken: approval }, ["resourceId", "releaseId", "dryRun"]) },
];
const TOOL_NAMES = new Set(TOOLS.map((tool) => tool.name));
export const MUTATION_TOOL_NAMES: ReadonlySet<string> = new Set(["restart_service", "deploy_commit", "rollback_deployment"]);

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean { return Object.keys(value).every((key) => allowed.includes(key)); }
function request(value: unknown): JsonRpcRequest | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  if (!hasOnlyKeys(item, ["jsonrpc", "id", "method", "params"]) || item.jsonrpc !== "2.0" || typeof item.method !== "string" || (item.id !== undefined && item.id !== null && typeof item.id !== "string" && typeof item.id !== "number")) return null;
  return item as unknown as JsonRpcRequest;
}
function success(id: JsonRpcRequest["id"], result: unknown): Record<string, unknown> { return { jsonrpc: "2.0", id: id ?? null, result }; }
function failure(id: JsonRpcRequest["id"], code: number, message: string, data?: unknown): Record<string, unknown> { return { jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } }; }
function emptyParams(params: unknown): boolean { return params === undefined || (!!params && typeof params === "object" && !Array.isArray(params) && Object.keys(params as Record<string, unknown>).length === 0); }
function actor(principal: McpPrincipal): string {
  const profile = principal.profileId ? `:${principal.profileId}` : "";
  const session = principal.sessionId ? `:${principal.sessionId}` : "";
  return `${principal.transport}:${principal.id}${profile}${session}`;
}
function visibleTools(principal: McpPrincipal): readonly ToolDefinition[] {
  if (!principal.allowedTools) return TOOLS;
  return TOOLS.filter((tool) => principal.allowedTools?.has(tool.name));
}
function resourceAllowed(principal: McpPrincipal, args: Record<string, unknown>): boolean {
  if (!principal.allowedResources) return true;
  return typeof args.resourceId === "string" && principal.allowedResources.has(args.resourceId);
}

export class McpServer {
  constructor(private readonly executor: ToolExecutor) {}

  async handle(value: unknown, principal: McpPrincipal = STDIO_PRINCIPAL, signal?: AbortSignal): Promise<Record<string, unknown> | null> {
    const message = request(value);
    if (!message) return failure(null, -32600, "Invalid Request");
    if (message.method === "notifications/initialized") {
      if (message.id === undefined) return null;
      return failure(message.id, -32602, "Invalid params");
    }
    if (message.method === "ping") return emptyParams(message.params) ? success(message.id, {}) : failure(message.id, -32602, "Invalid params");
    if (message.method === "initialize") return success(message.id, { protocolVersion: "2025-03-26", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "opshaven", version: "1.0.0" }, instructions: "Use configured logical resource IDs only. Mutations require an external human approval token." });
    if (message.method === "tools/list") return emptyParams(message.params) ? success(message.id, { tools: visibleTools(principal) }) : failure(message.id, -32602, "Invalid params");
    if (message.method === "tools/call") {
      if (!message.params || typeof message.params !== "object" || Array.isArray(message.params)) return failure(message.id, -32602, "Invalid params");
      const params = message.params as Record<string, unknown>;
      if (!hasOnlyKeys(params, ["name", "arguments", "_meta"]) || typeof params.name !== "string" || !TOOL_NAMES.has(params.name) || (principal.allowedTools && !principal.allowedTools.has(params.name)) || !params.arguments || typeof params.arguments !== "object" || Array.isArray(params.arguments)) return failure(message.id, -32602, "Unknown tool or invalid arguments");
      const args = { ...(params.arguments as Record<string, unknown>) };
      if (!resourceAllowed(principal, args)) return failure(message.id, -32602, "Unknown tool or invalid arguments");
      const approvalToken = typeof args.approvalToken === "string" ? args.approvalToken : undefined;
      if (args.approvalToken !== undefined && !approvalToken) return failure(message.id, -32602, "Approval token must be a string");
      if (approvalToken && (!MUTATION_TOOL_NAMES.has(params.name) || args.dryRun === true)) return failure(message.id, -32602, "Approval token is not accepted for this call");
      delete args.approvalToken;
      if (signal?.aborted) throw new Error("Operation was cancelled.");
      const result = await this.executor.execute(params.name, args, approvalToken, actor(principal), signal);
      return success(message.id, { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result, isError: !result.ok });
    }
    return failure(message.id, -32601, "Method not found");
  }
}

export function getToolDefinitions(): readonly ToolDefinition[] { return TOOLS; }
export type { OperationService };
