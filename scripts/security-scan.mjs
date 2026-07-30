import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";

const patterns = [
  ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/g],
  ["OpenAI-style secret", /\bsk-(?:proj|live)-[A-Za-z0-9_-]{20,}\b/g],
  ["AWS access key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ["long private-key block", /-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----[\s\S]{64,}?-----END [^-]*-----/g]
];

function scan(text, context) {
  const findings = [];
  for (const [label, pattern] of patterns) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) findings.push(`${context}: ${label}`);
  }
  return findings;
}

const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean);
const findings = [];
for (const file of files) {
  const buffer = await readFile(file);
  if (buffer.includes(0) || buffer.byteLength > 2_000_000) continue;
  findings.push(...scan(buffer.toString("utf8"), file));
}

const history = execFileSync("git", ["log", "HEAD", "-p", "--no-ext-diff", "--format=commit:%H"], {
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024
});
findings.push(...scan(history, "Candidate history"));

if (findings.length > 0) {
  console.error(findings.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`Security scan passed for ${files.length} tracked files and candidate history.`);
}
