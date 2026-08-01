import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { confirmationAccepted, executeFirstRunWizard, parseSshAddress } from "../src/operator-init.js";

async function command(executable: string, args: string[]): Promise<void> {
  const child = spawn(executable, args, { shell: false, stdio: ["ignore", "pipe", "pipe"] });
  await new Promise<void>((resolve, reject) => {
    let stderr = "";
    child.stderr.on("data", (chunk: Uint8Array) => { stderr += Buffer.from(chunk).toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code: number | null) => code === 0 ? resolve() : reject(new Error(stderr || `command exited ${code}`)));
  });
}

async function fixture(): Promise<{ root: string; identity: string; knownHosts: string }> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-init-wizard-"));
  const identity = path.join(root, "admin_id");
  const knownHosts = path.join(root, "known_hosts");
  await command("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", identity]);
  const publicKey = (await fs.readFile(`${identity}.pub`, "utf8")).trim();
  await fs.writeFile(knownHosts, `example.test ${publicKey}\n`, { mode: 0o644 });
  return { root, identity, knownHosts };
}

test("SSH address parsing separates operator labels from network addresses", () => {
  assert.deepEqual(parseSshAddress("example.test"), { host: "example.test", port: 22 });
  assert.deepEqual(parseSshAddress("example.test:2202"), { host: "example.test", port: 2202 });
  assert.deepEqual(parseSshAddress("[2001:db8::1]:2222"), { host: "2001:db8::1", port: 2222 });
  assert.deepEqual(parseSshAddress("2001:db8::1"), { host: "2001:db8::1", port: 22 });
  assert.throws(() => parseSshAddress("example.test:70000"), /SSH port/);
});

test("confirmation defaults remain explicit and predictable", () => {
  assert.equal(confirmationAccepted("", true), true);
  assert.equal(confirmationAccepted("", false), false);
  assert.equal(confirmationAccepted("yes", false), true);
  assert.equal(confirmationAccepted("Y", false), true);
  assert.equal(confirmationAccepted("no", true), false);
});

test("rejected host confirmation never invokes persistence", async () => {
  const files = await fixture();
  try {
    let initialized = 0;
    const output: string[] = [];
    await assert.rejects(() => executeFirstRunWizard([
      "--name", "PRIMARY",
      "--host", "example.test",
      "--admin-user", "root",
      "--admin-identity", files.identity,
      "--known-hosts", files.knownHosts,
      "--source-sha", "a".repeat(40),
    ], {
      interactive: true,
      ask: async (question) => question.startsWith("Use this host identity") ? "n" : "",
      write: (value) => output.push(value),
      initialize: async () => { initialized += 1; },
    }), /Host identity was not accepted/);
    assert.equal(initialized, 0);
    assert.match(output.join(""), /Detected host identity:/);
    assert.doesNotMatch(output.join(""), /PRIVATE KEY|BEGIN [A-Z ]+ KEY/);
  } finally {
    await fs.rm(files.root, { recursive: true, force: true });
  }
});

test("accepted wizard delegates one complete validated initialization", async () => {
  const files = await fixture();
  try {
    const captured: string[][] = [];
    await executeFirstRunWizard([
      "--name", "PRIMARY",
      "--host", "example.test",
      "--admin-user", "root",
      "--admin-identity", files.identity,
      "--known-hosts", files.knownHosts,
      "--source-sha", "b".repeat(40),
    ], {
      interactive: true,
      ask: async () => "y",
      write: () => {},
      initialize: async (args) => { captured.push([...args]); },
    });
    assert.equal(captured.length, 1);
    const args = captured[0] ?? [];
    assert.deepEqual(args.slice(0, 7), ["--non-interactive", "--host", "example.test", "--port", "22", "--admin-user", "root"]);
    assert.ok(args.includes("--host-key-sha256"));
    assert.ok(args.includes("--known-hosts"));
    assert.ok(args.includes("--admin-identity"));
    assert.ok(args.includes("--source-sha"));
  } finally {
    await fs.rm(files.root, { recursive: true, force: true });
  }
});
