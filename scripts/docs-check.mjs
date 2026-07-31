import { promises as fs } from "node:fs";
import path from "node:path";

const required = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE", "docs/operator-workflow.md", "docs/setup.md", "docs/security.md", "docs/architecture.md", "docs/confinement.md", "docs/reproducible-builds.md", "docs/sudoers.example", "security/capability-declaration.json"];
const obsolete = ["docs/milestones.md", "RELEASE_NOTES.md", "docs/operations.md", "docs/threat-model.md", "docs/release.md"];
const failures = [];
for (const file of required) {
  const text = await fs.readFile(file, "utf8").catch(() => null);
  if (text === null) failures.push(`${file}: missing`);
  else if (text.trim().length < 20) failures.push(`${file}: unexpectedly empty`);
}
const repositoryReferences = [...required.filter((file) => file.endsWith(".md")), "scripts/bootstrap-remote.sh", "package.json", ".github/workflows/ci.yml", ".github/workflows/security.yml", ".github/workflows/codeql.yml", ".github/workflows/release-verification.yml"];
for (const file of repositoryReferences) {
  const text = await fs.readFile(file, "utf8").catch(() => "");
  for (const deleted of obsolete) if (text.includes(deleted)) failures.push(`${file}: references deleted ${deleted}`);
}
for (const file of required.filter((item) => item.endsWith(".md"))) {
  const text = await fs.readFile(file, "utf8");
  for (const match of text.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const target = match[1].trim();
    if (!target || target.startsWith("#") || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
    const resolved = path.resolve(path.dirname(file), target.split("#", 1)[0]);
    if (!await fs.stat(resolved).then(() => true).catch(() => false)) failures.push(`${file}: broken link ${target}`);
  }
}
const readme = await fs.readFile("README.md", "utf8");
for (const target of ["docs/operator-workflow.md", "docs/setup.md", "docs/security.md", "CONTRIBUTING.md", "LICENSE"]) if (!readme.includes(`](${target})`)) failures.push(`README.md: missing link to ${target}`);
if (failures.length) { console.error([...new Set(failures)].join("\n")); process.exitCode = 1; }
else console.log(`docs: ${required.length} required files and internal links checked`);
