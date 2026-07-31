import assert from "node:assert/strict";
import test from "node:test";
import type { VerifiedCapability } from "../src/capabilities.js";
import { McpServer, type ToolExecutor } from "../src/mcp.js";
import { CapabilityBoundPrincipalVerifier } from "../src/remote-mcp/capability.js";
import type { PrincipalVerifier } from "../src/remote-mcp/http.js";

const capability: VerifiedCapability = {
  hash: "c".repeat(64),
  payload: {
    version: 1,
    mode: "read-only",
    policyVersion: "v1",
    allowedOperations: ["get_host_summary", "get_service_status"],
    allowedResources: { get_host_summary: ["host.main"], get_service_status: ["svc.web"] },
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    dispatcherSha256: "d".repeat(64),
    issuedAt: "2026-07-31T00:00:00.000Z",
    expiresAt: "2026-08-01T00:00:00.000Z",
  },
};
const base: PrincipalVerifier = { async verify() { return Object.freeze({ id: "subject", profileId: "readonly", transport: "streamable-http" as const, allowedTools: new Set(["get_host_summary", "get_service_status", "restart_service"]), allowedResources: new Set(["host.main", "host.other", "svc.other"]) }); } };
const identity = { authorization: "Bearer fixture", remoteAddress: "127.0.0.1", requestTarget: "/mcp", headers: {} };

test("signed read-only capability intersects profile tools and resources exactly", async () => {
  const verifier = new CapabilityBoundPrincipalVerifier(base, capability);
  const principal = await verifier.verify(identity);
  assert.deepEqual([...principal.allowedTools ?? []], ["get_host_summary", "get_service_status"]);
  assert.deepEqual([...principal.allowedResourcesByTool?.get("get_host_summary") ?? []], ["host.main"]);
  assert.deepEqual([...principal.allowedResourcesByTool?.get("get_service_status") ?? []], []);
  assert.equal(principal.allowedTools?.has("restart_service"), false);
});

test("remote discovery excludes mutations and calls enforce per-tool resources", async () => {
  let calls = 0;
  const executor: ToolExecutor = { async execute(operation) { calls += 1; return { ok: true, requestId: "req", operation, data: {}, meta: { startedAt: "s", finishedAt: "f", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } }; } };
  const principal = await new CapabilityBoundPrincipalVerifier(base, capability).verify(identity);
  const server = new McpServer(executor);
  const listed = await server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, principal);
  assert.deepEqual(((listed?.result as any).tools as any[]).map((tool) => tool.name), ["get_host_summary", "get_service_status"]);
  const deniedMutation = await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "restart_service", arguments: { resourceId: "svc.web", dryRun: true } } }, principal);
  assert.equal((deniedMutation?.error as any).code, -32602);
  const deniedWrongResource = await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.other" } } }, principal);
  assert.equal((deniedWrongResource?.error as any).code, -32602);
  const allowed = await server.handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "get_host_summary", arguments: { resourceId: "host.main" } } }, principal);
  assert.equal((allowed?.result as any).structuredContent.ok, true);
  assert.equal(calls, 1);
});

test("controlled capabilities cannot be attached to remote MCP", () => {
  assert.throws(() => new CapabilityBoundPrincipalVerifier(base, { ...capability, payload: { ...capability.payload, mode: "controlled" } }));
});
