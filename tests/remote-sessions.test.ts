import assert from "node:assert/strict";
import test from "node:test";
import type { McpPrincipal } from "../src/mcp.js";
import type { EnabledRemoteMcpConfig } from "../src/remote-mcp/config.js";
import { RemoteSessionManager } from "../src/remote-mcp/sessions.js";

const config = {
  sessions: { maximumGlobal: 2, maximumPerPrincipal: 1, lifetimeSeconds: 120, inactivitySeconds: 30, maximumPendingPerSession: 1 },
  profiles: [{ id: "readonly", sessionLimits: { maximumSessions: 1, lifetimeSeconds: 120, inactivitySeconds: 30, maximumPendingRequests: 1 } }],
} as unknown as EnabledRemoteMcpConfig;
const alice: McpPrincipal = Object.freeze({ id: "alice", profileId: "readonly", transport: "streamable-http" });
const bob: McpPrincipal = Object.freeze({ id: "bob", profileId: "readonly", transport: "streamable-http" });

test("sessions are random, principal-bound, protocol-bound, and replay resistant", () => {
  let now = 1000;
  const manager = new RemoteSessionManager(config, () => now);
  const session = manager.create(alice, "2025-11-25");
  assert.match(session, /^[A-Za-z0-9_-]{43}$/);
  assert.throws(() => manager.create(alice, "2025-11-25"));
  assert.throws(() => manager.acquire(session, bob, "2025-11-25", 1));
  assert.throws(() => manager.acquire(session, alice, "2025-03-26", 1));
  const lease = manager.acquire(session, alice, "2025-11-25", 1);
  assert.equal(lease.principal.sessionId, session);
  assert.throws(() => manager.acquire(session, alice, "2025-11-25", 2));
  lease.release();
  assert.throws(() => manager.acquire(session, alice, "2025-11-25", 1), /replayed/);
  const second = manager.acquire(session, alice, "2025-11-25", 2);
  second.release();
  now += 31000;
  assert.throws(() => manager.acquire(session, alice, "2025-11-25", 3));
});

test("session deletion and shutdown invalidate all state", () => {
  const manager = new RemoteSessionManager(config);
  const session = manager.create(alice, "2025-11-25");
  manager.delete(session, alice);
  assert.equal(manager.size(), 0);
  assert.throws(() => manager.acquire(session, alice, "2025-11-25", 1));
  const second = manager.create(alice, "2025-11-25");
  assert.equal(manager.size(), 1);
  manager.close();
  assert.equal(manager.size(), 0);
  assert.throws(() => manager.acquire(second, alice, "2025-11-25", 2));
  assert.throws(() => manager.create(alice, "2025-11-25"));
});
