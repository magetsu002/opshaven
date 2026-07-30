import assert from "node:assert/strict";
import test from "node:test";
import { getToolDefinitions, McpServer, type ToolExecutor } from "../src/mcp.js";

const executor: ToolExecutor = { async execute(operation) { return { ok: true, requestId: "req", operation, data: { safe: true }, meta: { startedAt: "start", finishedAt: "end", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };

test("MCP exposes exactly the V1 operation tools", () => {
  assert.equal(getToolDefinitions().length, 15);
  assert.equal(getToolDefinitions().some((tool) => tool.name.includes("shell") || tool.name.includes("exec")), false);
  for (const tool of getToolDefinitions()) assert.equal(tool.inputSchema.additionalProperties, false);
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
