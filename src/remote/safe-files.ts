import { promises as fs } from "node:fs";
import path from "node:path";
import { OpsHavenError } from "../errors.js";

export async function readTrustedTextFile(filePath: string, maxBytes: number): Promise<string> {
  if (!path.isAbsolute(filePath) || path.normalize(filePath) !== filePath || filePath.includes("..")) throw new OpsHavenError("POLICY_DENIED", "Unsafe configured file path.");
  const stat = await fs.lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) throw new OpsHavenError("POLICY_DENIED", "Configured file is not a safe bounded regular file.");
  const handle = await fs.open(filePath, "r");
  try {
    const afterOpen = await handle.stat();
    if (afterOpen.dev !== stat.dev || afterOpen.ino !== stat.ino || afterOpen.size !== stat.size) throw new OpsHavenError("POLICY_DENIED", "Configured file changed during validation.");
    return await handle.readFile({ encoding: "utf8" });
  } finally {
    await handle.close();
  }
}

export function parseEnvironmentPresence(text: string, expectedKeys: readonly string[]): Record<string, { present: boolean }> {
  const present = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=/.exec(trimmed);
    if (match?.[1]) present.add(match[1]);
  }
  return Object.fromEntries(expectedKeys.map((key) => [key, { present: present.has(key) }]));
}
