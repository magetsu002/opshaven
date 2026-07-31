import assert from "node:assert/strict";
import test from "node:test";
import type { McpPrincipal } from "../src/mcp.js";
import type { EnabledRemoteMcpConfig } from "../src/remote-mcp/config.js";
import { RemoteAdmissionController, validateHeaderLimits, validateJsonComplexity, withRemoteTimeout } from "../src/remote-mcp/limits.js";

const principal: McpPrincipal = Object.freeze({ id: "subject", profileId: "readonly", transport: "streamable-http" });
const config = {
  rateLimits: { windowSeconds: 60, maximumRequests: 3 },
  requests: { globalConcurrency: 1, perPrincipalConcurrency: 1, maximumQueue: 1, timeoutMs: 50 },
  profiles: [{ id: "readonly", rateLimits: { windowSeconds: 60, maximumRequests: 3, concurrency: 1 } }],
} as unknown as EnabledRemoteMcpConfig;

test("header and JSON structural limits fail before processing", () => {
  assert.doesNotThrow(() => validateHeaderLimits({ host: "localhost", accept: "application/json" }, 4, 128));
  assert.throws(() => validateHeaderLimits({ a: "1", b: "2", c: "3" }, 2, 128));
  assert.throws(() => validateHeaderLimits({ host: "x".repeat(200) }, 4, 32));
  assert.doesNotThrow(() => validateJsonComplexity({ a: [1, 2] }, 4, 8));
  assert.throws(() => validateJsonComplexity({ a: { b: { c: 1 } } }, 3, 16));
  assert.throws(() => validateJsonComplexity({ a: 1, b: 2, c: 3 }, 4, 3));
});

test("admission enforces concurrency, bounded queue, and rate limits", async () => {
  let now = 1000;
  const admission = new RemoteAdmissionController(config, () => now);
  const first = await admission.acquire(principal);
  const queued = admission.acquire(principal);
  await assert.rejects(admission.acquire(principal));
  assert.equal(admission.active(), 1);
  assert.equal(admission.queued(), 1);
  first.release();
  const second = await queued;
  assert.equal(admission.active(), 1);
  second.release();
  await assert.rejects(admission.acquire(principal));
  now += 61000;
  const reset = await admission.acquire(principal);
  reset.release();
  admission.close();
  await assert.rejects(admission.acquire(principal));
});

test("remote timeout aborts active work deterministically", async () => {
  let aborted = false;
  await assert.rejects(withRemoteTimeout(async (signal) => await new Promise<void>((_resolve, reject) => {
    signal.addEventListener("abort", () => { aborted = true; reject(new Error("aborted")); }, { once: true });
  }), 10));
  assert.equal(aborted, true);
});
