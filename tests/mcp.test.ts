import assert from "node:assert/strict";
import test from "node:test";
import { getToolDefinitions, McpServer, STDIO_PRINCIPAL, type McpPrincipal, type ToolExecutor } from "../src/mcp.js";
import { getPackageVersion } from "../src/version.js";

const executor: ToolExecutor = { async execute(operation) { return { ok: true, requestId: "req", operation, data: { safe: true }, meta: { startedAt: "start", finishedAt: "end", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };

test("MCP exposes one stable compiled V1.3 tool catalogue", () => {
  assert.equal(getToolDefinitions().length, 38);
  assert.equal(getToolDefinitions().some((tool) => tool.name === "run_command"), true);
  assert.equal(getToolDefinitions().some((tool) => tool.name === "workspace_info"), true);
  assert.equal(getToolDefinitions().some((tool) => tool.name === "project_state"), true);
  assert.equal(getToolDefinitions().some((tool) => tool.name === "verify_workspace"), true);
  assert.equal(getToolDefinitions().some((tool) => tool.name === "source_runtime_state"), true);
  assert.equal(getToolDefinitions().some((tool) => tool.name === "prepare_verified_deployment"), true);
  assert.equal(getToolDefinitions().some((tool) => tool.name === "run_shell" || tool.name === "exec"), false);
  for (const tool of getToolDefinitions()) assert.equal(tool.inputSchema.additionalProperties, false);
});

test("stdio initialization uses package version and stable discovery", async () => {
  const server = new McpServer(executor);
  const initialized = await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, STDIO_PRINCIPAL);
  assert.deepEqual(initialized, {
    jsonrpc: "2.0",
    id: 1,
    result: {
      protocolVersion: "2025-03-26",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "opshaven", version: await getPackageVersion() },
      instructions: "Use registered workspaces for bounded project context, exact source and verification evidence, source-to-runtime comparison, edits, and explicitly enabled project execution. Prepare deployment only from a clean committed revision with current passing verification evidence. Remote operations remain bounded by configured applications and environments.",
    },
  });
  const listed = await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, STDIO_PRINCIPAL);
  assert.equal(((listed?.result as Record<string, unknown>).tools as unknown[]).length, 38);
  const called = await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" } } }, STDIO_PRINCIPAL);
  assert.equal(((called?.result as Record<string, unknown>).structuredContent as Record<string, unknown>).ok, true);
  assert.equal((await server.handle({ jsonrpc: "2.0", id: 4, method: "missing" }, STDIO_PRINCIPAL))?.error && true, true);
  assert.equal(await server.handle({ jsonrpc: "2.0", method: "notifications/initialized" }, STDIO_PRINCIPAL), null);
});

test("principal authorization does not mutate discovery and remains enforced at tools/call", async () => {
  const calls: Array<{ operation: string; actor?: string }> = [];
  const recording: ToolExecutor = { async execute(operation, _args, _approval, actor) { calls.push({ operation, ...(actor ? { actor } : {}) }); return { ok: true, requestId: "req", operation, data: {}, meta: { startedAt: "start", finishedAt: "end", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };
  const principal: McpPrincipal = Object.freeze({ id: "subject-1", transport: "streamable-http", profileId: "readonly", sessionId: "session-1", allowedTools: new Set(["get_host_summary"]), allowedResources: new Set(["host.main"]) });
  const server = new McpServer(recording);
  const listed = await server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, principal);
  assert.deepEqual((((listed?.result as Record<string, unknown>).tools as Array<Record<string, unknown>>).map((tool) => tool.name)), getToolDefinitions().map((tool) => tool.name));
  const deniedTool = await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "restart_service", arguments: { resourceId: "svc.web", dryRun: true } } }, principal);
  assert.equal((deniedTool?.error as Record<string, unknown>).code, -32602);
  const deniedLocalTool = await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "workspace_info", arguments: { workspaceId: "project" } } }, principal);
  assert.equal((deniedLocalTool?.error as Record<string, unknown>).code, -32602);
  const deniedResource = await server.handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.other" } } }, principal);
  assert.equal((deniedResource?.error as Record<string, unknown>).code, -32602);
  await server.handle({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" } } }, principal);
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

test("MCP rejects approval tokens on read-only, local, and dry-run calls", async () => {
  let calls = 0;
  const counting: ToolExecutor = { async execute(operation) { calls += 1; return { ok: true, requestId: "req", operation, data: {}, meta: { startedAt: "start", finishedAt: "end", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };
  const server = new McpServer(counting);
  const read = await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main", approvalToken: "x".repeat(64) } } });
  assert.equal((read?.error as Record<string, unknown>).code, -32602);
  const local = await server.handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "workspace_info", arguments: { workspaceId: "project", approvalToken: "x".repeat(64) } } });
  assert.equal((local?.error as Record<string, unknown>).code, -32602);
  const dry = await server.handle({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "restart_service", arguments: { resourceId: "svc.web", dryRun: true, approvalToken: "x".repeat(64) } } });
  assert.equal((dry?.error as Record<string, unknown>).code, -32602);
  assert.equal(calls, 0);
});

test("tool result uses stable structured envelope", async () => {
  const response = await new McpServer(executor).handle({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" } } });
  const result = response?.result as Record<string, unknown>;
  assert.equal((result.structuredContent as Record<string, unknown>).ok, true);
});
