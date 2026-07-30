import path from "node:path";
import { OpsHavenError } from "../errors.js";
import { readRegularTextFile } from "../safe-fs.js";

export async function readTrustedTextFile(filePath: string, maxBytes: number): Promise<string> {
  if (!path.isAbsolute(filePath) || path.normalize(filePath) !== filePath || filePath.includes("..")) throw new OpsHavenError("POLICY_DENIED", "Unsafe configured file path.");
  return await readRegularTextFile(filePath, "Configured remote file", { maxBytes, code: "POLICY_DENIED" });
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
