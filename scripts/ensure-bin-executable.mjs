import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targets = [
  "dist/src/cli-entry.js",
  "dist/src/mcp-entry.js",
  "dist/src/remote/dispatcher.js",
  "dist-readonly/src/remote/read-only-dispatcher.js",
];

for (const relative of targets) {
  const target = path.join(repositoryRoot, relative);
  const stat = await fs.lstat(target);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Package binary target is not a regular file: ${relative}`);
  }
  const handle = await fs.open(target, "r");
  try {
    const buffer = Buffer.alloc(64);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (!buffer.subarray(0, bytesRead).toString("utf8").startsWith("#!/usr/bin/env node\n")) {
      throw new Error(`Package binary target has no supported Node.js shebang: ${relative}`);
    }
  } finally {
    await handle.close();
  }
  await fs.chmod(target, 0o755);
  const verified = await fs.lstat(target);
  if (!verified.isFile() || verified.isSymbolicLink() || (verified.mode & 0o111) === 0) {
    throw new Error(`Package binary target is not an executable regular file: ${relative}`);
  }
}
