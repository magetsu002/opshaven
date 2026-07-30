import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { McpStdioServer } from "../src/mcp/server.js";
import { MCP_TOOLS } from "../src/mcp/tools.js";
import type { OperationsService } from "../src/service/operations-service.js";

async function exchange(messages: readonly unknown[], service: OperationsService): Promise<readonly Record<string, unknown>[]> {
  const input = new PassThrough();
  const output = new PassThrough();
  output.setEncoding("utf8");
  let text = "";
  output.on("data", (chunk: string) => {
    text += chunk;
  });
  const running = new McpStdioServer(service, input, output).run();
  input.end(`${messages.map((message) => JSON.stringify(message)).join("\n")}\n`);
  await running;
  return text
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

const fakeService = {
  call: async (operation: string) => ({
    ok: true as const,
    operation,
    requestId: "00000000-0000-4000-8000-000000000000",
    hostId: "demo-host",
    observedAt: "2026-01-01T00:00:00.000Z",
    data: { safe: true },
    truncated: false
  })
} as unknown as OperationsService;

describe("MCP stdio integration", () => {
  it("supports modern discovery and legacy initialization", async () => {
    const responses = await exchange(
      [
        { jsonrpc: "2.0", id: 1, method: "server/discover", params: {} },
        {
          jsonrpc: "2.0",
          id: 2,
          method: "initialize",
          params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "test", version: "1" } }
        }
      ],
      fakeService
    );
    const discover = responses[0]?.result as Record<string, unknown>;
    assert.ok((discover.supportedVersions as unknown[]).includes("2026-07-28"));
    const initialize = responses[1]?.result as Record<string, unknown>;
    assert.equal(initialize.protocolVersion, "2025-11-25");
  });

  it("lists every operation with strict schemas in deterministic order", async () => {
    const [message] = await exchange([{ jsonrpc: "2.0", id: "tools", method: "tools/list", params: {} }], fakeService);
    const result = message?.result as { tools: Array<{ name: string; inputSchema: Record<string, unknown> }> };
    assert.equal(result.tools.length, 15);
    assert.deepEqual(result.tools.map((tool) => tool.name), MCP_TOOLS.map((tool) => tool.name));
    assert.ok(result.tools.every((tool) => tool.inputSchema.additionalProperties === false));
  });

  it("returns structured tool envelopes and rejects unknown tools as protocol errors", async () => {
    const responses = await exchange(
      [
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "get_host_summary", arguments: { hostId: "demo-host" } }
        },
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "shell", arguments: {} } }
      ],
      fakeService
    );
    const result = responses[0]?.result as Record<string, unknown>;
    assert.equal((result.structuredContent as Record<string, unknown>).ok, true);
    assert.equal((responses[1]?.error as Record<string, unknown>).code, -32602);
  });

  it("rejects malformed and oversized messages without writing non-JSON stdout", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    output.setEncoding("utf8");
    let text = "";
    output.on("data", (chunk: string) => {
      text += chunk;
    });
    const running = new McpStdioServer(fakeService, input, output).run();
    input.write("not-json\n");
    input.end(`${"x".repeat(1_048_577)}\n`);
    await running;
    const responses = text.trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.equal((responses[0]?.error as Record<string, unknown>).code, -32700);
    assert.equal((responses[1]?.error as Record<string, unknown>).code, -32600);
  });
});
