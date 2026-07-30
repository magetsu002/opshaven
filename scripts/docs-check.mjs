import { promises as fs } from "node:fs";

const VERSION = "1.0.0";
const required = [
  "README.md",
  "RELEASE_NOTES.md",
  "docs/architecture.md",
  "docs/operations.md",
  "docs/release.md",
  "docs/security.md",
  "docs/setup.md",
  "docs/threat-model.md",
];
const failures = [];
for (const file of required) {
  const text = await fs.readFile(file, "utf8").catch(() => null);
  if (text === null) failures.push(`${file}: missing`);
  else if (text.trim().length < 40) failures.push(`${file}: unexpectedly empty`);
}
const packageJson = JSON.parse(await fs.readFile("package.json", "utf8"));
const lock = JSON.parse(await fs.readFile("package-lock.json", "utf8"));
const mcp = await fs.readFile("src/mcp.ts", "utf8");
const readme = await fs.readFile("README.md", "utf8");
const notes = await fs.readFile("RELEASE_NOTES.md", "utf8");
if (packageJson.version !== VERSION) failures.push("package.json: version mismatch");
if (lock.version !== VERSION || lock.packages?.[""]?.version !== VERSION) failures.push("package-lock.json: version mismatch");
if (!mcp.includes(`version: "${VERSION}"`)) failures.push("src/mcp.ts: MCP version mismatch");
if (!readme.includes(`OpsHaven ${VERSION}`)) failures.push("README.md: stable release version missing");
for (const heading of ["Security model", "Deployment and rollback", "Known V1 limitations"]) {
  if (!notes.includes(heading)) failures.push(`RELEASE_NOTES.md: missing ${heading}`);
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`docs: ${required.length + 4} release references checked`);
}
