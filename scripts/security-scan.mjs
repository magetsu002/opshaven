import { promises as fs } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const excluded = new Set([".git", "node_modules", "dist", "coverage", "generated"]);
const files = [];
async function walk(root) {
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (entry.isFile() && (await fs.stat(full)).size <= 1024 * 1024) files.push(full);
  }
}
await walk(".");
const patterns = [
  [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, "private key material"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, "cloud access key"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/, "repository token"],
  [/\b(?:ERITORIUM|VERTICAL CITY|vertical-city)\b/i, "unrelated private-project marker"],
  [/StrictHostKeyChecking=no/, "disabled SSH host-key checking"],
  [/shell\s*:\s*true/, "shell-enabled subprocess"]
];
const failures = [];
for (const file of files) {
  if (file === "scripts/security-scan.mjs" || file === "scripts/lint.mjs") continue;
  const text = await fs.readFile(file, "utf8").catch(() => "");
  for (const [pattern, label] of patterns) if (pattern.test(text)) failures.push(`${file}: ${label}`);
}
async function gitHistoryContains(pattern) {
  return await new Promise((resolve) => {
    const child = spawn("/usr/bin/git", ["log", "--all", "-G", pattern, "--format=%H", "--"], { shell: false, stdio: ["ignore", "pipe", "ignore"] });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk.toString(); });
    child.on("close", () => resolve(output.trim().length > 0));
    child.on("error", () => resolve(false));
  });
}
for (const marker of ["ERITORIUM", "VERTICAL CITY", "vertical-city"]) if (await gitHistoryContains(marker)) failures.push(`git history: unrelated private-project marker ${marker}`);
if (failures.length) { console.error(failures.join("\n")); process.exitCode = 1; }
else console.log(`security-scan: ${files.length} files and Git history checked`);
