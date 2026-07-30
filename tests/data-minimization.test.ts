import assert from "node:assert/strict";
import test from "node:test";
import { OpsHavenError } from "../src/errors.js";
import { sanitizeOutput } from "../src/redaction.js";
import { parseUfwSummary } from "../src/remote/firewall-summary.js";
import { parseEnvironmentPresence } from "../src/remote/safe-files.js";

const limits = { maxBytes: 4096, maxLines: 50 };

test("environment inspection returns presence only", () => {
  const result = parseEnvironmentPresence(
    "API_TOKEN=planted-secret-value\nEMPTY=\n# PASSWORD=ignored\n",
    ["API_TOKEN", "EMPTY", "PASSWORD"],
  );
  assert.deepEqual(result, {
    API_TOKEN: { present: true },
    EMPTY: { present: true },
    PASSWORD: { present: false },
  });
  assert.equal(JSON.stringify(result).includes("planted-secret-value"), false);
});

test("firewall inspection returns bounded counts rather than rule text", () => {
  const summary = parseUfwSummary(
    [
      "Status: active",
      "Logging: on (low)",
      "Default: deny (incoming), allow (outgoing), disabled (routed)",
      "[ 1] 22/tcp ALLOW IN 203.0.113.4",
      "[ 2] 443/tcp (v6) LIMIT IN Anywhere (v6)",
      "comment token=planted-secret-value",
    ].join("\n"),
    limits,
  );
  assert.equal(summary.status, "active");
  assert.equal(summary.rules.total, 2);
  assert.equal(summary.rules.allow, 1);
  assert.equal(summary.rules.limit, 1);
  assert.equal(summary.rules.ipv6, 1);
  const serialized = JSON.stringify(summary);
  assert.equal(serialized.includes("203.0.113.4"), false);
  assert.equal(serialized.includes("planted-secret-value"), false);
});

test("malicious log controls cannot bypass secret redaction or inject terminal output", () => {
  const splitToken = "ghp_ABCDEFGHIJ\u001b[31mKLMNOPQRSTUVWXYZ";
  const result = sanitizeOutput(
    `prefix\u202E ${splitToken}\u001b[0m\nAuthorization: Bearer planted-token-value\n`,
    limits,
  );
  assert.equal(result.text.includes("ghp_"), false);
  assert.equal(result.text.includes("planted-token-value"), false);
  assert.equal(/[\u001b\u202a-\u202e\u2066-\u2069]/u.test(result.text), false);
  assert.ok(result.redactions >= 4);
});

test("zero-width redaction bypass attempts are normalized before matching", () => {
  const result = sanitizeOutput("api_key=sec\u200bret-value\n", limits);
  assert.equal(result.text.includes("secret-value"), false);
  assert.equal(result.text.includes("sec"), false);
  assert.ok(result.redactions >= 2);
});

test("oversized output is truncated and binary output is rejected", () => {
  const result = sanitizeOutput("one\ntwo\nthree\n", { maxBytes: 8, maxLines: 2 });
  assert.equal(result.truncated, true);
  assert.ok(result.lineCount <= 2);
  assert.throws(
    () => sanitizeOutput("safe\u0000binary", limits),
    (error: unknown) => error instanceof OpsHavenError && error.code === "BINARY_OUTPUT",
  );
});
