import assert from "node:assert/strict";
import test from "node:test";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import type { HostResource } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";
import { fingerprintSecret, sanitizeOutput } from "../src/redaction.js";
import type { RemoteRequest } from "../src/remote/protocol.js";
import { buildSshArgs, SshTransport } from "../src/transport/ssh.js";

const host: HostResource = { id: "host.main", kind: "host", address: "example.internal", port: 22, user: "opshaven", knownHostsFile: "/etc/opshaven/known_hosts", identityFile: "/etc/opshaven/id_ed25519", connectTimeoutMs: 5000 };
const request: RemoteRequest = { version: 1, requestId: "req-ssh", operation: "get_host_summary", resourceId: "host.main", args: { resourceId: "host.main" }, limits: { timeoutMs: 1000, maxBytes: 4096, maxLines: 20 } };

async function tempRoot(): Promise<string> { return await fs.mkdtemp(path.join(tmpdir(), "opshaven-ssh-")); }

test("SSH arguments enforce host keys and disable interactive features", () => {
  const args = buildSshArgs(host);
  assert.ok(args.includes("StrictHostKeyChecking=yes"));
  assert.ok(args.includes("ClearAllForwardings=yes"));
  assert.ok(args.includes("ForwardAgent=no"));
  assert.ok(args.includes("RequestTTY=no"));
  assert.equal(args.at(-1), "opshaven@example.internal");
  assert.equal(args.some((arg) => arg.includes("bash") || arg.includes("sh -c")), false);
});

test("SSH transport rejects symlinked or permissive trust files before spawning", async () => {
  const root = await tempRoot();
  const identity = path.join(root, "identity");
  const knownHosts = path.join(root, "known_hosts");
  await fs.writeFile(identity, "private", { mode: 0o600 });
  await fs.writeFile(knownHosts, "host key", { mode: 0o644 });
  let spawned = false;
  const transport = new SshTransport((() => { spawned = true; throw new Error("must not spawn"); }) as any);
  const linkedIdentity = path.join(root, "linked_identity");
  await fs.symlink(identity, linkedIdentity);
  await assert.rejects(transport.execute({ ...host, identityFile: linkedIdentity, knownHostsFile: knownHosts }, request), (error: unknown) => error instanceof OpsHavenError && error.code === "SSH_FAILED");
  assert.equal(spawned, false);
  const linkedKnownHosts = path.join(root, "linked_known_hosts");
  await fs.symlink(knownHosts, linkedKnownHosts);
  await assert.rejects(transport.execute({ ...host, identityFile: identity, knownHostsFile: linkedKnownHosts }, request), (error: unknown) => error instanceof OpsHavenError && error.code === "SSH_HOST_KEY_FAILED");
  assert.equal(spawned, false);
  await fs.chmod(identity, 0o644);
  await assert.rejects(transport.execute({ ...host, identityFile: identity, knownHostsFile: knownHosts }, request), (error: unknown) => error instanceof OpsHavenError && error.code === "SSH_FAILED");
  assert.equal(spawned, false);
});

test("redaction removes common credentials before bounding output", () => {
  const result = sanitizeOutput("Authorization: Bearer abc.def.ghi\nDATABASE_URL=postgres://user:pass@example/db\ntoken=super-secret\nlast", { maxBytes: 4096, maxLines: 3 });
  assert.equal(result.text.includes("super-secret"), false);
  assert.equal(result.text.includes("user:pass"), false);
  assert.equal(result.truncated, true);
});

test("redaction removes generic URLs and configured secret fingerprints", () => {
  const planted = "planted-secret-value";
  const result = sanitizeOutput(`callback=https://example.internal/private/path\nvalue=${planted}`, { maxBytes: 4096, maxLines: 10 }, [fingerprintSecret(planted)]);
  assert.equal(result.text.includes("example.internal"), false);
  assert.equal(result.text.includes(planted), false);
  assert.equal(result.redactions, 2);
});

test("binary output is rejected", () => {
  assert.throws(() => sanitizeOutput("ok\u0000secret", { maxBytes: 4096, maxLines: 10 }));
});
