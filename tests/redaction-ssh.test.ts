import assert from "node:assert/strict";
import test from "node:test";
import { sanitizeOutput } from "../src/redaction.js";
import { buildSshArgs } from "../src/transport/ssh.js";
import type { HostResource } from "../src/config.js";

const host: HostResource = { id: "host.main", kind: "host", address: "example.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id_ed25519", connectTimeoutMs: 5000 };

test("SSH arguments enforce host keys and disable interactive features", () => {
  const args = buildSshArgs(host);
  assert.ok(args.includes("StrictHostKeyChecking=yes"));
  assert.ok(args.includes("ClearAllForwardings=yes"));
  assert.ok(args.includes("ForwardAgent=no"));
  assert.ok(args.includes("RequestTTY=no"));
  assert.equal(args.at(-1), "opshaven@example.internal");
  assert.equal(args.some((arg) => arg.includes("bash") || arg.includes("sh -c")), false);
});

test("redaction removes common credentials before bounding output", () => {
  const result = sanitizeOutput("Authorization: Bearer abc.def.ghi\nDATABASE_URL=postgres://user:pass@example/db\ntoken=super-secret\nlast", { maxBytes: 4096, maxLines: 3 });
  assert.equal(result.text.includes("super-secret"), false);
  assert.equal(result.text.includes("user:pass"), false);
  assert.equal(result.truncated, true);
});

test("binary output is rejected", () => {
  assert.throws(() => sanitizeOutput("ok\u0000secret", { maxBytes: 4096, maxLines: 10 }));
});
