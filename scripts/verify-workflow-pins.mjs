import { promises as fs } from "node:fs";
import path from "node:path";

const root = ".github/workflows";
const failures = [];
for (const entry of await fs.readdir(root, { withFileTypes: true })) {
  if (!entry.isFile() || !/\.ya?ml$/.test(entry.name)) continue;
  const file = path.join(root, entry.name);
  const text = await fs.readFile(file, "utf8");
  for (const match of text.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)\s*$/gm)) {
    const reference = match[1];
    if (reference.startsWith("./")) continue;
    if (!/@[a-f0-9]{40}$/.test(reference)) failures.push(`${file}: action is not pinned to a full commit SHA: ${reference}`);
  }
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log("workflows: all external actions are pinned to full commit SHAs");
}
