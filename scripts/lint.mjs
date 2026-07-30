import { readdir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";

const roots = ["src", "tests", "scripts"];
const violations = [];

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await walk(path);
      continue;
    }
    if (![".ts", ".mjs"].includes(extname(path))) continue;
    const text = await readFile(path, "utf8");
    text.split("\n").forEach((line, index) => {
      if (/\s+$/.test(line)) violations.push(`${path}:${index + 1}: trailing whitespace`);
      if (line.includes("\t")) violations.push(`${path}:${index + 1}: tab character`);
    });
  }
}

for (const root of roots) await walk(root);
if (violations.length > 0) {
  console.error(violations.join("\n"));
  process.exitCode = 1;
}
