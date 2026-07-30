import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { before, describe, it } from "node:test";
import type { OpsHavenConfig } from "../src/config/schema.js";
import { parseConfig } from "../src/config/schema.js";
import { Dispatcher } from "../src/dispatcher/dispatcher.js";
import { createLogHandlers } from "../src/dispatcher/log-handlers.js";
import { redactText } from "../src/security/redaction.js";

let config: OpsHavenConfig;

before(async () => {
  const raw = JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as {
    secrets: { fingerprints: string[]; keyNames: string[] };
  };
  raw.secrets.fingerprints.push("planted-secret-123");
  config = parseConfig(raw);
});

describe("secret-safe bounded logs", () => {
  it("redacts credentials, headers, cookies, URLs, JWTs, keys, and fingerprints", () => {
    const input = [
      "authorization: Bearer abcdefghijklmnop",
      "cookie: session=abcd",
      "https://user:pass@example.invalid/path?token=abc",
      "token=supersecret",
      "eyJabcdefgh.abcdefghijkl.abcdefghijk",
      "planted-secret-123",
      "-----BEGIN PRIVATE KEY----- abc -----END PRIVATE KEY-----"
    ].join("\n");
    const output = redactText(input, config.secrets);
    for (const secret of ["abcdefghijklmnop", "session=abcd", "user:pass", "supersecret", "planted-secret-123"]) {
      assert.ok(!output.includes(secret));
    }
    assert.ok(output.includes("[REDACTED"));
  });

  it("uses fixed journalctl arguments and returns only redacted text", async () => {
    const calls: string[][] = [];
    const handlers = createLogHandlers({
      runner: async (request) => {
        calls.push([...request.args]);
        return {
          exitCode: 0,
          stdout: Buffer.from("token=supersecret\nauthorization: Bearer abcdefghijklmnop\nnormal line"),
          stderr: Buffer.alloc(0)
        };
      }
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle({
      version: 1,
      requestId: "00000000-0000-4000-8000-000000000000",
      operation: "get_redacted_logs",
      target: "demo-service",
      args: { serviceId: "demo-service", lines: 3, window: "1h" },
      expectedState: {},
      dryRun: false,
      limits: { timeoutMs: 1000, maxBytes: 4096, maxLines: 10 }
    });
    assert.equal(response.ok, true);
    assert.ok(!JSON.stringify(response).includes("supersecret"));
    assert.ok(calls[0]?.includes("demo.service"));
    assert.ok(!calls[0]?.includes("sh"));
  });
});
