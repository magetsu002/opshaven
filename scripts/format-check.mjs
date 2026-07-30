import { promises as fs } from "node:fs";
import path from "node:path";

const roots = ["src", "tests", "scripts", "docs", "integration", "examples"];
const rootFiles = [
  "README.md",
  "RELEASE_NOTES.md",
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "tsconfig.build.json",
  "tsconfig.readonly.json",
];
const files = [];

async function walk(root) {
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    if (entry.name === "generated") continue;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (/\.(?:ts|mjs|js|json|md|yml|yaml|sh|py|service)$/.test(entry.name) || entry.name === "Dockerfile") files.push(full);
  }
}

for (const root of roots) await walk(root);
files.push(...rootFiles);
const failures = [];
for (const file of [...new Set(files)].sort()) {
  const text = await fs.readFile(file, "utf8");
  if (text.includes("\r\n")) failures.push(`${file}: CRLF line endings are not allowed`);
  if (!text.endsWith("\n")) failures.push(`${file}: final newline is required`);
  text.split("\n").forEach((line, index) => {
    if (/[ \t]+$/.test(line)) failures.push(`${file}:${index + 1}: trailing whitespace`);
  });
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`format: ${new Set(files).size} files checked`);
}
