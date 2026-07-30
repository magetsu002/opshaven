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

test("tool result uses stable structured envelope", async () => {
  const response = await new McpServer(executor).handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" } } });
  const result = response?.result as Record<string, unknown>;
  assert.equal((result.structuredContent as Record<string, unknown>).ok, true);
});
