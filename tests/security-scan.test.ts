import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";

async function run(command: string, args: readonly string[], cwd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Uint8Array) => { stdout += Buffer.from(chunk).toString("utf8"); });
    child.stderr.on("data", (chunk: Uint8Array) => { stderr += Buffer.from(chunk).toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code: number | null) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function git(cwd: string, ...args: string[]): Promise<void> {
  const result = await run("/usr/bin/git", args, cwd);
  assert.equal(result.code, 0, result.stderr);
}

test("history scan ignores detector definitions but catches tracked leaks", async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-scan-"));
  await fs.mkdir(path.join(root, "scripts"), { recursive: true });
  await fs.mkdir(path.join(root, "docs"), { recursive: true });
  await fs.copyFile(path.resolve("scripts/security-scan.mjs"), path.join(root, "scripts/security-scan.mjs"));
  await fs.writeFile(path.join(root, "docs/safe.md"), "generic fixture\n");
  await git(root, "init", "-q");
  await git(root, "config", "user.name", "OpsHaven Test");
  await git(root, "config", "user.email", "test@example.invalid");
  await git(root, "add", ".");
  await git(root, "commit", "-qm", "initial detector");

  const clean = await run(process.execPath, ["scripts/security-scan.mjs"], root);
  assert.equal(clean.code, 0, clean.stderr);

  const plantedMarker = ["ERI", "TORIUM"].join("");
  await fs.writeFile(path.join(root, "docs/leak.md"), `${plantedMarker}\n`);
  await git(root, "add", "docs/leak.md");
  await git(root, "commit", "-qm", "plant leak");

  const leaked = await run(process.execPath, ["scripts/security-scan.mjs"], root);
  assert.equal(leaked.code, 1);
  assert.match(leaked.stderr, /unrelated private-project marker/);
});
