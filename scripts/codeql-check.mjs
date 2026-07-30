import { promises as fs } from "node:fs";
import path from "node:path";

const root = process.argv[2];
if (!root) throw new Error("A CodeQL SARIF directory is required.");
const files = [];
async function walk(directory) {
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (entry.isFile() && entry.name.endsWith(".sarif")) files.push(full);
  }
}
await walk(root);
if (files.length === 0) throw new Error("CodeQL produced no SARIF output.");
const findings = [];
for (const file of files) {
  const document = JSON.parse(await fs.readFile(file, "utf8"));
  for (const run of document.runs ?? []) {
    for (const result of run.results ?? []) {
      findings.push({
        ruleId: result.ruleId ?? "unknown",
        level: result.level ?? "warning",
        message: result.message?.text ?? "CodeQL finding",
      });
    }
  }
}
if (findings.length > 0) {
  console.error(JSON.stringify({ findings }, null, 2));
  process.exitCode = 1;
} else {
  console.log(`CodeQL: ${files.length} SARIF file(s), zero findings`);
}
