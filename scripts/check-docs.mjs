import { access, readFile, readdir } from "node:fs/promises";
import { dirname, join, normalize, resolve } from "node:path";

const root = process.cwd();
const required = [
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "docs/architecture.md",
  "docs/threat-model.md",
  "docs/security.md",
  "docs/configuration.md",
  "docs/dispatcher.md",
  "docs/setup.md",
  "docs/mcp-client.md",
  "docs/operations.md",
  "docs/deployment.md",
  "docs/release.md"
];

async function markdownFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist" || entry.name === ".test-dist") continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await markdownFiles(path));
    else if (entry.isFile() && entry.name.endsWith(".md")) files.push(path);
  }
  return files;
}

for (const path of required) await access(resolve(root, path));

const failures = [];
for (const file of await markdownFiles(root)) {
  const text = await readFile(file, "utf8");
  for (const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = match[1];
    if (target.startsWith("http://") || target.startsWith("https://") || target.startsWith("#") || target.startsWith("mailto:")) continue;
    const withoutAnchor = target.split("#", 1)[0];
    if (withoutAnchor.length === 0) continue;
    const resolved = normalize(resolve(dirname(file), decodeURIComponent(withoutAnchor)));
    if (!resolved.startsWith(root)) {
      failures.push(`${file}: link escapes repository: ${target}`);
      continue;
    }
    try {
      await access(resolved);
    } catch {
      failures.push(`${file}: missing link target: ${target}`);
    }
  }
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exit(1);
}
process.stdout.write(`Documentation check passed for ${required.length} required documents.\n`);
