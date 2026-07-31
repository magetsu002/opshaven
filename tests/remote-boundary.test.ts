import assert from "node:assert/strict";
import test from "node:test";
import { validateHttpBoundary } from "../src/remote-mcp/boundary.js";

const policy = {
  allowedOrigins: ["https://chat.example.test"],
  allowedHosts: ["mcp.example.test", "localhost:43110"],
  trustedProxies: ["127.0.0.2"],
};

test("direct HTTP boundary accepts exact host and allowed or absent origin", () => {
  assert.deepEqual(validateHttpBoundary(policy, "127.0.0.1", { host: "mcp.example.test", origin: "https://chat.example.test" }), { host: "mcp.example.test", origin: "https://chat.example.test", proxied: false });
  assert.deepEqual(validateHttpBoundary(policy, "127.0.0.1", { host: "localhost:43110" }), { host: "localhost:43110", proxied: false });
});

test("HTTP boundary rejects unexpected origins, hosts, and untrusted forwarding", () => {
  assert.throws(() => validateHttpBoundary(policy, "127.0.0.1", { host: "mcp.example.test", origin: "https://evil.example.test" }));
  assert.throws(() => validateHttpBoundary(policy, "127.0.0.1", { host: "evil.example.test" }));
  assert.throws(() => validateHttpBoundary(policy, "127.0.0.1", { host: "mcp.example.test", "x-forwarded-host": "mcp.example.test" }));
  assert.throws(() => validateHttpBoundary(policy, "127.0.0.1", { host: "mcp.example.test", origin: "*" }));
});

test("trusted proxy boundary requires a complete unambiguous HTTPS forwarding set", () => {
  const accepted = validateHttpBoundary(policy, "::ffff:127.0.0.2", { host: "localhost:43110", "x-forwarded-for": "2001:db8::1", "x-forwarded-host": "mcp.example.test", "x-forwarded-proto": "https" });
  assert.deepEqual(accepted, { host: "mcp.example.test", proxied: true });
  assert.throws(() => validateHttpBoundary(policy, "127.0.0.2", { host: "localhost:43110", "x-forwarded-for": "2001:db8::1", "x-forwarded-host": ["mcp.example.test", "evil.example.test"], "x-forwarded-proto": "https" }));
  assert.throws(() => validateHttpBoundary(policy, "127.0.0.2", { host: "localhost:43110", forwarded: "host=mcp.example.test" }));
  assert.throws(() => validateHttpBoundary(policy, "127.0.0.2", { host: "localhost:43110", "x-forwarded-for": "2001:db8::1", "x-forwarded-host": "mcp.example.test", "x-forwarded-proto": "http" }));
});
