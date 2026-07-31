import assert from "node:assert/strict";
import { CapabilityBoundPrincipalVerifier } from "../../dist/src/remote-mcp/capability.js";
import { CURRENT_MCP_PROTOCOL, RemoteAuthenticationError, StreamableHttpServer } from "../../dist/src/remote-mcp/http.js";
import { McpServer } from "../../dist/src/mcp.js";

const disposableToken = "disposable-remote-mcp-token";
let operations = 0;
const executor = {
  async execute(operation) {
    operations += 1;
    return { ok: true, requestId: "podman-request", operation, data: { synthetic: true }, meta: { startedAt: "s", finishedAt: "f", dryRun: false, mutation: false, truncated: false, redactions: 0, auditRecorded: true } };
  },
};
const injected = {
  async verify(identity) {
    if (identity.authorization !== `Bearer ${disposableToken}`) throw new RemoteAuthenticationError();
    return Object.freeze({
      id: "disposable-principal",
      profileId: "readonly-podman",
      transport: "streamable-http",
      allowedTools: new Set(["get_host_summary", "restart_service"]),
      allowedResources: new Set(["host.synthetic"]),
    });
  },
};
const capability = {
  hash: "c".repeat(64),
  payload: {
    version: 1,
    mode: "read-only",
    policyVersion: "podman-v1",
    allowedOperations: ["get_host_summary"],
    allowedResources: { get_host_summary: ["host.synthetic"] },
    limits: { timeoutMs: 2000, maxBytes: 65536, maxLines: 500 },
    dispatcherSha256: "d".repeat(64),
    issuedAt: "2026-07-31T00:00:00.000Z",
    expiresAt: "2027-07-31T00:00:00.000Z"
  }
};
const origin = "https://hosted-client.example.test";
const forwardedHost = "mcp-tunnel.example.test";
const server = new StreamableHttpServer({
  mcp: new McpServer(executor),
  verifier: new CapabilityBoundPrincipalVerifier(injected, capability),
  boundary: { allowedOrigins: [origin], allowedHosts: [forwardedHost], trustedProxies: ["127.0.0.1"] },
  limits: { maximumBodyBytes: 65536, maximumHeaderBytes: 16384, maximumHeaders: 48, maximumJsonDepth: 16, maximumJsonNodes: 2048, maximumResponseBytes: 262144, timeoutMs: 5000, maximumConnections: 8 },
});
const started = await server.start();

function message(method, params = {}, id = 1) {
  return { jsonrpc: "2.0", id, method, params: { ...params, _meta: { "io.modelcontextprotocol/protocolVersion": CURRENT_MCP_PROTOCOL, "io.modelcontextprotocol/clientCapabilities": {} } } };
}
async function post(body, { token = disposableToken, requestOrigin = origin } = {}) {
  const method = body.method;
  const name = method === "tools/call" ? body.params?.name : undefined;
  return await fetch(started.url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      accept: "application/json",
      origin: requestOrigin,
      "x-forwarded-for": "2001:db8::10",
      "x-forwarded-host": forwardedHost,
      "x-forwarded-proto": "https",
      "mcp-protocol-version": CURRENT_MCP_PROTOCOL,
      "mcp-method": method,
      ...(name ? { "mcp-name": name } : {}),
    },
    body: JSON.stringify(body),
  });
}

try {
  const unauthenticated = await post(message("tools/list"), { token: "wrong" });
  assert.equal(unauthenticated.status, 401);
  const wrongOrigin = await post(message("tools/list"), { requestOrigin: "https://untrusted.example.test" });
  assert.equal(wrongOrigin.status, 403);

  const discovery = await post(message("server/discover"));
  assert.equal(discovery.status, 200);
  assert.equal((await discovery.json()).result.protocolVersion, CURRENT_MCP_PROTOCOL);

  const list = await post(message("tools/list"));
  const listed = await list.json();
  assert.deepEqual(listed.result.tools.map((tool) => tool.name), ["get_host_summary"]);

  const call = await post(message("tools/call", { name: "get_host_summary", arguments: { resourceId: "host.synthetic" } }, 2));
  const called = await call.json();
  assert.equal(called.result.structuredContent.ok, true);
  assert.equal(called.result.structuredContent.data.synthetic, true);

  const mutation = await post(message("tools/call", { name: "restart_service", arguments: { resourceId: "svc.synthetic", dryRun: true } }, 3));
  assert.equal((await mutation.json()).error.code, -32602);
  assert.equal(operations, 1);
} finally {
  await server.close();
}
await assert.rejects(fetch(started.url));
process.stdout.write("remote-mcp-podman: rootless localhost transport, trusted proxy boundary, disposable authentication, read-only capability, tool call, mutation denial, and shutdown passed\n");
