import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { buildRuntimeManifest } from "../src/setup/install.js";

const required = [
  "src/capabilities.js",
  "src/capability-declaration.js",
  "src/config.js",
  "src/errors.js",
  "src/safe-fs.js",
  "src/remote/authenticated-protocol.js",
  "src/remote/confinement.js",
  "src/remote/read-only-dispatcher.js",
  "src/remote/read-only-handlers.js",
  "src/remote/read-only-policy.js",
  "src/remote/read-only-protocol.js",
  "src/remote/runner.js",
];

async function fixture(root: string): Promise<void> {
  for (const relative of required) {
    const filePath = path.join(root, ...relative.split("/"));
    await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
    await fs.writeFile(filePath, `export const value = ${JSON.stringify(relative)};\n`, { mode: 0o600 });
  }
}

test("runtime manifest rejects a symlink substituted for a reviewed runtime file", async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-runtime-race-"));
  const outside = path.join(root, "outside.js");
  try {
    await fixture(root);
    await fs.writeFile(outside, "export const secret = true;\n", { mode: 0o600 });
    const target = path.join(root, "src", "remote", "runner.js");
    await fs.rm(target);
    await fs.symlink(outside, target);
    await assert.rejects(buildRuntimeManifest(root), /symbolic links|safe regular non-symlink file/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("runtime manifest source uses descriptor-safe nofollow reads instead of check-then-read", async () => {
  const source = await fs.readFile(path.join(process.cwd(), "src", "setup", "install.ts"), "utf8");
  const manifestSection = source.slice(source.indexOf("export async function buildRuntimeManifest"), source.indexOf("export function renderReadonlyWrapper"));
  assert.equal(manifestSection.includes("readRuntimeFile(fullPath)"), true);
  assert.equal(manifestSection.includes("fs.readFile(fullPath)"), false);
  assert.equal(manifestSection.includes("fs.lstat(fullPath)"), false);
});
