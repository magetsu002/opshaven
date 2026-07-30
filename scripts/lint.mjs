import { promises as fs } from "node:fs";
import path from "node:path";

const roots = ["src", "tests", "scripts"];
const files = [];
async function walk(root) {
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (/\.(?:ts|mjs)$/.test(entry.name)) files.push(full);
  }
}
for (const root of roots) await walk(root);
const forbidden = [
  [/(?<!\.)\b(?:exec|execSync)\s*\(/, "Use spawn with fixed executable and argument arrays"],
  [/shell\s*:\s*true/, "Shell execution is forbidden"],
  [/StrictHostKeyChecking=no/, "Host-key verification cannot be disabled"],
  [/\bssh\s+[^\n]*-[tA]/, "PTY or agent forwarding must not be enabled"],
  [/\b(?:ERITORIUM|VERTICAL CITY|vertical-city)\b/i, "Private-project marker detected"]
];
const failures = [];
for (const file of files) {
  if (file === "scripts/lint.mjs" || file === "scripts/security-scan.mjs") continue;
  const text = await fs.readFile(file, "utf8");
  for (const [pattern, message] of forbidden) if (pattern.test(text)) failures.push(`${file}: ${message}`);
  if (/\r\n/.test(text)) failures.push(`${file}: CRLF line endings are not allowed`);
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`lint: ${files.length} files checked`);
}
