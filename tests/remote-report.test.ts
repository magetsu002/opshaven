import assert from "node:assert/strict";
import test from "node:test";
import type { RemoteMcpConfig } from "../src/remote-mcp/config.js";
import { remoteBoundaryAssertions, remoteMcpUrl, summarizeRemoteTrust } from "../src/remote-mcp/report.js";

const enabled = {
  enabled: true,
  bindHost: "127.0.0.1",
  port: 43110,
  path: "/mcp",
  allowedOrigins: ["https://chat.example.test"],
  allowedHosts: ["mcp.example.test"],
  trustedProxies: [],
  oauth: { issuer: "https://issuer.example.test", audience: "opshaven", requiredScopes: ["mcp:invoke"], allowedAlgorithms: ["EdDSA"] },
  profiles: [{ id: "readonly", capability: "read-only", allowedTools: ["get_host_summary"] }],
} as unknown as RemoteMcpConfig;

test("remote report states disabled-by-default and safe enabled assumptions", () => {
  const disabled = summarizeRemoteTrust({ enabled: false });
  assert.equal(disabled.enabled, false);
  assert.equal(remoteBoundaryAssertions({ enabled: false }).every((item) => item.passed), true);
  const summary = summarizeRemoteTrust(enabled);
  assert.equal(summary.enabled, true);
  assert.equal(summary.authentication, "oidc-bearer");
  assert.equal(summary.readOnly, true);
  assert.equal(remoteBoundaryAssertions(enabled).every((item) => item.passed), true);
  assert.equal(remoteMcpUrl(enabled), "http://127.0.0.1:43110/mcp");
});

test("remote boundary verification fails public binding or mutation exposure", () => {
  const publicBinding = { ...(enabled as any), bindHost: "0.0.0.0" } as RemoteMcpConfig;
  assert.equal(remoteBoundaryAssertions(publicBinding).find((item) => item.name.includes("loopback"))?.passed, false);
  const mutation = { ...(enabled as any), profiles: [{ id: "unsafe", capability: "read-only", allowedTools: ["restart_service"] }] } as RemoteMcpConfig;
  assert.equal(remoteBoundaryAssertions(mutation).find((item) => item.name.includes("read-only"))?.passed, false);
});
