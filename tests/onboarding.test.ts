import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { detectKnownHostFingerprint } from "../src/operator-state.js";

interface Result { code: number | null; stdout: string; stderr: string }

async function run(command: string, args: string[], env: Record<string, string | undefined> = {}): Promise<Result> {
  const child = spawn(command, args, {
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", ...env },
  });
  return await new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Onboarding process timed out."));
    }, 15000);
    child.stdout.on("data", (chunk: Uint8Array) => { stdout += Buffer.from(chunk).toString("utf8"); });
    child.stderr.on("data", (chunk: Uint8Array) => { stderr += Buffer.from(chunk).toString("utf8"); });
    child.on("error", (error: unknown) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code: number | null) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

async function runCli(args: string[], home: string): Promise<Result> {
  return await run(process.execPath, [path.join(process.cwd(), "dist/src/cli-entry.js"), ...args], { HOME: home, NO_COLOR: "" });
}

async function generateSshKey(filePath: string): Promise<void> {
  const result = await run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", filePath]);
  assert.equal(result.code, 0, result.stderr);
  await fs.chmod(filePath, 0o600);
  await fs.chmod(`${filePath}.pub`, 0o644);
}

async function writeKnownHost(keyPath: string, knownHosts: string, host: string, port: number): Promise<string> {
  const publicKey = (await fs.readFile(`${keyPath}.pub`, "utf8")).trim();
  const target = port === 22 ? host : `[${host}]:${port}`;
  await fs.writeFile(knownHosts, `${target} ${publicKey}\n`, { mode: 0o644 });
  const fingerprint = await detectKnownHostFingerprint(host, port, knownHosts);
  if (!fingerprint) throw new Error("Expected a derived host fingerprint.");
  assert.match(fingerprint, /^SHA256:[A-Za-z0-9+/]{20,60}$/);
  return fingerprint;
}

test("empty environment initializes local state and reports the next action", async () => {
  const home = await fs.mkdtemp(path.join(tmpdir(), "opshaven-onboarding-local-"));
  try {
    const initialized = await runCli(["init", "--local-only"], home);
    assert.equal(initialized.code, 0);
    assert.match(initialized.stdout, /OpsHaven first-time setup/);
    assert.match(initialized.stdout, /✓ Operator environment detected/);
    assert.match(initialized.stdout, /✓ Local authorization keys prepared/);
    assert.match(initialized.stdout, /Next:\nopshaven setup remote/);
    assert.equal(initialized.stderr, "");
    assert.doesNotMatch(initialized.stdout, /PRIVATE KEY|BEGIN [A-Z ]+ KEY|approval-secret|operator-private/);

    const root = path.join(home, ".config", "opshaven");
    const privateStat = await fs.stat(path.join(root, "keys", "operator-private.pem"));
    assert.equal(privateStat.mode & 0o077, 0);

    const doctor = await runCli(["doctor"], home);
    assert.equal(doctor.code, 1);
    assert.match(doctor.stdout, /^OpsHaven Health/);
    assert.match(doctor.stdout, /Local environment\n✓ Operator setup ready/);
    assert.match(doctor.stdout, /Remote connection\n✗ Remote setup not configured/);
    assert.match(doctor.stdout, /Next action\n  opshaven setup remote/);
    assert.doesNotMatch(doctor.stdout, /capability|declaration binding|dispatcher hash|\.json|\.pem/i);

    const setup = await runCli(["setup", "remote", "--non-interactive", "--dry-run"], home);
    assert.equal(setup.code, 1);
    assert.match(setup.stderr, /Setup is not initialized\./);
    assert.match(setup.stderr, /opshaven init/);
    assert.doesNotMatch(setup.stderr, /schema|RemoteSetupConfig|capability/i);
  } finally {
    await fs.rm(home, { recursive: true, force: true });
  }
});

test("empty host identity is rejected without persisting initialization state", async () => {
  const home = await fs.mkdtemp(path.join(tmpdir(), "opshaven-onboarding-empty-host-"));
  try {
    const adminIdentity = path.join(home, "admin_id");
    const knownHosts = path.join(home, "known_hosts");
    await generateSshKey(adminIdentity);
    const publicKey = (await fs.readFile(`${adminIdentity}.pub`, "utf8")).trim();
    await fs.writeFile(knownHosts, `unrelated.example ${publicKey}\n`, { mode: 0o644 });
    const initialized = await runCli([
      "init",
      "--non-interactive",
      "--host", "127.0.0.1",
      "--port", "2222",
      "--admin-user", "root",
      "--admin-identity", adminIdentity,
      "--known-hosts", knownHosts,
      "--host-key-sha256", "",
      "--source-sha", "a".repeat(40),
    ], home);
    assert.equal(initialized.code, 1);
    assert.match(initialized.stderr, /Host identity unavailable\./);
    assert.match(initialized.stderr, /Host identity could not be verified/);
    const root = path.join(home, ".config", "opshaven");
    await assert.rejects(() => fs.readFile(path.join(root, "state.json"), "utf8"));
    await assert.rejects(() => fs.readFile(path.join(root, "setup.json"), "utf8"));
  } finally {
    await fs.rm(home, { recursive: true, force: true });
  }
});

test("guided initialization accepts a valid pinned host identity", async () => {
  const home = await fs.mkdtemp(path.join(tmpdir(), "opshaven-onboarding-remote-"));
  try {
    const adminIdentity = path.join(home, "admin_id");
    const knownHosts = path.join(home, "known_hosts");
    await generateSshKey(adminIdentity);
    const fingerprint = await writeKnownHost(adminIdentity, knownHosts, "127.0.0.1", 2222);
    const sourceSha = "a".repeat(40);
    const initialized = await runCli([
      "init",
      "--non-interactive",
      "--host", "127.0.0.1",
      "--port", "2222",
      "--admin-user", "root",
      "--admin-identity", adminIdentity,
      "--known-hosts", knownHosts,
      "--host-key-sha256", fingerprint,
      "--source-sha", sourceSha,
    ], home);
    assert.equal(initialized.code, 0, initialized.stderr);
    assert.doesNotMatch(initialized.stdout, /config\.json|setup\.json|operator-private|approval-secret/);

    const root = path.join(home, ".config", "opshaven");
    const setupPath = path.join(root, "setup.json");
    const configPath = path.join(root, "config.json");
    const [originalSetup, originalConfig] = await Promise.all([
      fs.readFile(setupPath, "utf8"),
      fs.readFile(configPath, "utf8"),
    ]);
    const parsedSetup = JSON.parse(originalSetup) as { target: { expectedHostKeySha256: string } };
    assert.equal(parsedSetup.target.expectedHostKeySha256, fingerprint);
    assert.doesNotThrow(() => JSON.parse(originalConfig));

    const dryRun = await runCli(["setup", "remote", "--dry-run"], home);
    assert.equal(dryRun.code, 0, dryRun.stderr);
    assert.match(dryRun.stdout, /Remote setup plan/);
    assert.doesNotMatch(dryRun.stdout, /PRIVATE KEY|BEGIN [A-Z ]+ KEY/);

    await fs.writeFile(setupPath, "{\"version\":2}\n", { mode: 0o600 });
    const translated = await runCli(["setup", "remote", "--dry-run"], home);
    assert.equal(translated.code, 1);
    assert.match(translated.stderr, /Setup state is missing or outdated\./);
    assert.match(translated.stderr, /Checked:\n✗ Saved setup state/);
    assert.match(translated.stderr, /opshaven init/);
    assert.doesNotMatch(translated.stderr, /version 1|schema/i);

    const debug = await runCli(["setup", "remote", "--dry-run", "--debug"], home);
    assert.equal(debug.code, 1);
    assert.match(debug.stderr, /remote setup configuration|version 1/i);

    await fs.writeFile(setupPath, originalSetup, { mode: 0o600 });
    const legacy = await runCli(["setup", "remote", "--dry-run", "--config", setupPath], home);
    assert.equal(legacy.code, 0, legacy.stderr);
    assert.match(legacy.stdout, /Remote setup plan/);
  } finally {
    await fs.rm(home, { recursive: true, force: true });
  }
});
