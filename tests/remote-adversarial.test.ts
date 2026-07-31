import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "../src/config.js";
import { McpServer, type McpPrincipal } from "../src/mcp.js";
import { OperationService, type RemoteTransport } from "../src/operations.js";
import type { RemoteRequest, RemoteResponse } from "../src/remote/protocol.js";
import { CURRENT_MCP_PROTOCOL, RemoteAuthenticationError, StreamableHttpServer, type PrincipalVerifier } from "../src/remote-mcp/http.js";

const config = parseConfig({
  version: 1,
  policyVersion: "v1",
  limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
  audit: { path: `/tmp/opshaven-remote-adversarial-${process.pid}.jsonl` },
  approvals: { directory: `/tmp/opshaven-remote-approvals-${process.pid}`, secretFile: `/tmp/opshaven-remote-secret-${process.pid}`, signingPrivateKeyFile: `/tmp/opshaven-remote-private-${process.pid}.pem`, verificationPublicKeyFile: `/tmp/opshaven-remote-public-${process.pid}.pem`, remoteUsedDirectory: `/tmp/opshaven-remote-used-${process.pid}`, defaultTtlSeconds: 300 },
  secretFingerprints: ["da6c2195916f072b2dc510f8c430913536c26e249f22a426120e541ebf7b2a6b"],
  resources: [{ id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id", connectTimeoutMs: 5000 }],
});

class CountingTransport implements RemoteTransport {
  calls = 0;
  async execute(_host: unknown, request: RemoteRequest, signal?: AbortSignal): Promise<RemoteResponse> {
    this.calls += 1;
    if (signal?.aborted) throw new Error("cancelled");
    return { version: 1, requestId: request.requestId, ok: true, data: { uname: "Linux", note: "planted-secret-value" }, evidence: { startedAt: "s", finishedAt: "f", truncated: false, redactions: 0 } };
  }
}
const principal: McpPrincipal = Object.freeze({ id: "subject", profileId: "readonly", transport: "streamable-http", allowedTools: new Set(["get_host_summary"]), allowedResources: new Set(["host.main"]) });
const verifier: PrincipalVerifier = { async verify(identity) { if (identity.authorization !== "Bearer fixture") throw new RemoteAuthenticationError(); return principal; } };

function modern(method: string, params: Record<string, unknown> = {}, id: number | undefined = 1): Record<string, unknown> {
  return { jsonrpc: "2.0", ...(id === undefined ? {} : { id }), method, params: { ...params, _meta: { "io.modelcontextprotocol/protocolVersion": CURRENT_MCP_PROTOCOL, "io.modelcontextprotocol/clientCapabilities": {} } } };
}
async function request(url: string, message: unknown, extra: Record<string, string> = {}, raw?: string): Promise<Response> {
  const method = (message as any)?.method ?? "tools/call";
  const name = method === "tools/call" ? (message as any)?.params?.name : undefined;
  return await fetch(url, { method: "POST", headers: { authorization: "Bearer fixture", "content-type": "application/json", accept: "application/json", origin: "https://chat.example.test", "mcp-protocol-version": CURRENT_MCP_PROTOCOL, "mcp-method": method, ...(name ? { "mcp-name": name } : {}), ...extra }, body: raw ?? JSON.stringify(message) });
}

async function fixture(maximumBodyBytes = 2048, maximumJsonDepth = 12) {
  const remote = new CountingTransport();
  const allowedHosts: string[] = [];
  const server = new StreamableHttpServer({
    mcp: new McpServer(new OperationService(config, remote)),
    verifier,
    boundary: { allowedOrigins: ["https://chat.example.test"], allowedHosts, trustedProxies: [] },
    limits: { maximumBodyBytes, maximumHeaderBytes: 8192, maximumHeaders: 48, maximumJsonDepth, maximumJsonNodes: 512, maximumResponseBytes: 65536, timeoutMs: 2000, maximumConnections: 8 },
  });
  const started = await server.start();
  allowedHosts.push(`127.0.0.1:${started.port}`);
  return { remote, server, url: started.url };
}

test("unauthenticated and malformed authorization never reach remote operations", async () => {
  const remote = new CountingTransport();
  const server = new StreamableHttpServer({ mcp: new McpServer(new OperationService(config, remote)), verifier });
  const started = await server.start();
  try {
    const response = await fetch(started.url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json", "mcp-protocol-version": CURRENT_MCP_PROTOCOL, "mcp-method": "tools/list" }, body: JSON.stringify(modern("tools/list")) });
    assert.equal(response.status, 401);
    assert.equal(remote.calls, 0);
  } finally {
    await server.close();
  }
});

test("origin, body, JSON, and MCP metadata failures occur before remote operations", async () => {
  const { remote, server, url } = await fixture(512, 8);
  try {
    assert.equal((await request(url, modern("tools/list"), { origin: "https://evil.example.test" })).status, 403);
    assert.equal((await request(url, modern("tools/list"), {}, "x".repeat(513))).status, 413);
    const deep = modern("tools/call", { name: "get_host_summary", arguments: { resourceId: "host.main", nested: { a: { b: { c: { d: { e: 1 } } } } } } });
    assert.equal((await request(url, deep)).status, 413);
    const mismatch = await request(url, modern("tools/list"), { "mcp-method": "tools/call" });
    assert.equal(mismatch.status, 400);
    assert.equal(remote.calls, 0);
  } finally {
    await server.close();
  }
});

test("unknown tools, resources, mutations, and runtime override attempts never reach remote operations", async () => {
  const { remote, server, url } = await fixture();
  try {
    const unknown = await request(url, modern("tools/call", { name: "run_shell", arguments: { resourceId: "host.main", command: "id" } }));
    assert.equal((await unknown.json() as any).error.code, -32602);
    const wrongResource = await request(url, modern("tools/call", { name: "get_host_summary", arguments: { resourceId: "host.other" } }));
    assert.equal((await wrongResource.json() as any).error.code, -32602);
    const mutation = await request(url, modern("tools/call", { name: "restart_service", arguments: { resourceId: "svc.web", dryRun: true } }));
    assert.equal((await mutation.json() as any).error.code, -32602);
    const overrides = await request(url, modern("tools/call", { name: "get_host_summary", arguments: { resourceId: "host.main", configPath: "/tmp/evil", executable: "/bin/sh", env: { PATH: "/tmp" }, shell: "id" } }));
    assert.equal((await overrides.json() as any).result.structuredContent.ok, false);
    assert.equal(remote.calls, 0);
  } finally {
    await server.close();
  }
});

test("authenticated read-only calls reach the shared operation service and remain redacted", async () => {
  const { remote, server, url } = await fixture();
  try {
    const response = await request(url, modern("tools/call", { name: "get_host_summary", arguments: { resourceId: "host.main" } }));
    assert.equal(response.status, 200);
    const text = await response.text();
    assert.equal(remote.calls, 1);
    assert.equal(text.includes("planted-secret-value"), false);
    assert.equal(text.includes("[REDACTED]"), true);
  } finally {
    await server.close();
  }
  await assert.rejects(fetch(url));
});
