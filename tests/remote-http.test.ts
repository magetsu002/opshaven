import assert from "node:assert/strict";
import test from "node:test";
import { McpServer, type ToolExecutor } from "../src/mcp.js";
import { CURRENT_MCP_PROTOCOL, StreamableHttpServer, type PrincipalVerifier } from "../src/remote-mcp/http.js";

const executor: ToolExecutor = { async execute(operation) { return { ok: true, requestId: "req", operation, data: { safe: true }, meta: { startedAt: "start", finishedAt: "end", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };
const verifier: PrincipalVerifier = { async verify() { return Object.freeze({ id: "subject", transport: "streamable-http" as const, allowedTools: new Set(["get_host_summary"]), allowedResources: new Set(["host.main"]) }); } };

async function post(url: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return await fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(body) });
}
function modern(method: string, params: Record<string, unknown> = {}): Record<string, unknown> {
  return { jsonrpc: "2.0", id: 1, method, params: { ...params, _meta: { "io.modelcontextprotocol/protocolVersion": CURRENT_MCP_PROTOCOL, "io.modelcontextprotocol/clientCapabilities": {} } } };
}

test("native Streamable HTTP handles discovery, calls, notifications, malformed input, and shutdown", async () => {
  const transport = new StreamableHttpServer({ mcp: new McpServer(executor), verifier });
  const started = await transport.start();
  assert.equal(started.host, "127.0.0.1");

  const discovery = await post(started.url, modern("server/discover"), { "mcp-protocol-version": CURRENT_MCP_PROTOCOL, "mcp-method": "server/discover" });
  assert.equal(discovery.status, 200);
  assert.equal((await discovery.json() as any).result.protocolVersion, CURRENT_MCP_PROTOCOL);

  const list = await post(started.url, modern("tools/list"), { "mcp-protocol-version": CURRENT_MCP_PROTOCOL, "mcp-method": "tools/list" });
  assert.equal(list.status, 200);
  assert.deepEqual((await list.json() as any).result.tools.map((tool: any) => tool.name), ["get_host_summary"]);

  const call = await post(started.url, modern("tools/call", { name: "get_host_summary", arguments: { resourceId: "host.main" } }), { "mcp-protocol-version": CURRENT_MCP_PROTOCOL, "mcp-method": "tools/call", "mcp-name": "get_host_summary" });
  assert.equal(call.status, 200);
  assert.equal((await call.json() as any).result.structuredContent.ok, true);

  const notificationBody = modern("notifications/initialized");
  delete (notificationBody as any).id;
  const notification = await post(started.url, notificationBody, { "mcp-protocol-version": CURRENT_MCP_PROTOCOL, "mcp-method": "notifications/initialized" });
  assert.equal(notification.status, 202);
  assert.equal(await notification.text(), "");

  const malformed = await fetch(started.url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: "{" });
  assert.equal(malformed.status, 400);
  const wrongType = await fetch(started.url, { method: "POST", headers: { "content-type": "text/plain", accept: "application/json" }, body: "{}" });
  assert.equal(wrongType.status, 415);
  const get = await fetch(started.url, { method: "GET", headers: { accept: "text/event-stream" } });
  assert.equal(get.status, 405);

  await transport.close();
  await assert.rejects(fetch(started.url));
});

test("legacy initialization remains available over native HTTP", async () => {
  const transport = new StreamableHttpServer({ mcp: new McpServer(executor), verifier });
  const started = await transport.start();
  const response = await post(started.url, { jsonrpc: "2.0", id: 9, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "fixture", version: "1" } } });
  assert.equal(response.status, 200);
  assert.equal((await response.json() as any).result.protocolVersion, "2025-03-26");
  await transport.close();
});

test("non-loopback binding is denied without the high-friction override", async () => {
  const transport = new StreamableHttpServer({ mcp: new McpServer(executor), verifier, bindHost: "0.0.0.0" });
  await assert.rejects(transport.start(), /unsafe-allow-non-loopback/);
});
