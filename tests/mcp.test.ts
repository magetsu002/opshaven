import assert from "node:assert/strict";
import test from "node:test";
import { getToolDefinitions, McpServer, STDIO_PRINCIPAL, type McpPrincipal, type ToolExecutor } from "../src/mcp.js";

const executor: ToolExecutor = { async execute(operation) { return { ok: true, requestId: "req", operation, data: { safe: true }, meta: { startedAt: "start", finishedAt: "end", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };

test("MCP exposes exactly the V1 operation tools", () => {
  assert.equal(getToolDefinitions().length, 15);
  assert.equal(getToolDefinitions().some((tool) => tool.name.includes("shell") || tool.name.includes("exec")), false);
  for (const tool of getToolDefinitions()) assert.equal(tool.inputSchema.additionalProperties, false);
});

test("stdio initialization, discovery, calls, errors, notifications, and shutdown framing remain stable", async () => {
  const server = new McpServer(executor);
  const initialized = await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, STDIO_PRINCIPAL);
  assert.deepEqual(initialized, { jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-03-26", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "opshaven", version: "1.0.0" }, instructions: "Use configured logical resource IDs only. Mutations require an external human approval token." } });
  const listed = await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, STDIO_PRINCIPAL);
  assert.equal(((listed?.result as Record<string, unknown>).tools as unknown[]).length, 15);
  const called = await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" } } }, STDIO_PRINCIPAL);
  assert.equal(((called?.result as Record<string, unknown>).structuredContent as Record<string, unknown>).ok, true);
  assert.equal((await server.handle({ jsonrpc: "2.0", id: 4, method: "missing" }, STDIO_PRINCIPAL))?.error && true, true);
  assert.equal(await server.handle({ jsonrpc: "2.0", method: "notifications/initialized" }, STDIO_PRINCIPAL), null);
});

test("principal context filters discovery, resource access, and audit actor", async () => {
  const calls: Array<{ operation: string; actor?: string }> = [];
  const recording: ToolExecutor = { async execute(operation, _args, _approval, actor) { calls.push({ operation, ...(actor ? { actor } : {}) }); return { ok: true, requestId: "req", operation, data: {}, meta: { startedAt: "start", finishedAt: "end", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };
  const principal: McpPrincipal = Object.freeze({ id: "subject-1", transport: "streamable-http", profileId: "readonly", sessionId: "session-1", allowedTools: new Set(["get_host_summary"]), allowedResources: new Set(["host.main"]) });
  const server = new McpServer(recording);
  const listed = await server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, principal);
  assert.deepEqual((((listed?.result as Record<string, unknown>).tools as Array<Record<string, unknown>>).map((tool) => tool.name)), ["get_host_summary"]);
  const deniedTool = await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "restart_service", arguments: { resourceId: "svc.web", dryRun: true } } }, principal);
  assert.equal((deniedTool?.error as Record<string, unknown>).code, -32602);
  const deniedResource = await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.other" } } }, principal);
  assert.equal((deniedResource?.error as Record<string, unknown>).code, -32602);
  await server.handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" } } }, principal);
  assert.deepEqual(calls, [{ operation: "get_host_summary", actor: "streamable-http:subject-1:readonly:session-1" }]);
});

test("unknown MCP tools fail closed", async () => {
  const response = await new McpServer(executor).handle({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "run_shell", arguments: { command: "id" } } });
  assert.equal((response?.error as Record<string, unknown>).code, -32602);
});

test("MCP rejects unknown envelope and call fields", async () => {
  const server = new McpServer(executor);
  const envelope = await server.handle({ jsonrpc: "2.0", id: 1, method: "ping", surprise: true });
  assert.equal((envelope?.error as Record<string, unknown>).code, -32600);
  const params = await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" }, extra: true } });
  assert.equal((params?.error as Record<string, unknown>).code, -32602);
});

test("MCP never responds to initialized notifications", async () => {
  const server = new McpServer(executor);
  assert.equal(await server.handle({ jsonrpc: "2.0", method: "notifications/initialized", params: { unexpected: true } }), null);
});

test("MCP rejects approval tokens on read-only and dry-run calls", async () => {
  let calls = 0;
  const counting: ToolExecutor = { async execute(operation) { calls += 1; return { ok: true, requestId: "req", operation, data: {}, meta: { startedAt: "start", finishedAt: "end", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };
  const server = new McpServer(counting);
  const read = await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main", approvalToken: "x".repeat(64) } } });
  assert.equal((read?.error as Record<string, unknown>).code, -32602);
  const dry = await server.handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "restart_service", arguments: { resourceId: "svc.web", dryRun: true, approvalToken: "x".repeat(64) } } });
  assert.equal((dry?.error as Record<string, unknown>).code, -32602);
  assert.equal(calls, 0);
});

test("tool result uses stable structured envelope", async () => {
  const response = await new McpServer(executor).handle({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" } } });
  const result = response?.result as Record<string, unknown>;
  assert.equal((result.structuredContent as Record<string, unknown>).ok, true);
});
