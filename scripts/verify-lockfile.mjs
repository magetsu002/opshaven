import { promises as fs } from "node:fs";

const pkg = JSON.parse(await fs.readFile("package.json", "utf8"));
const lock = JSON.parse(await fs.readFile("package-lock.json", "utf8"));
const failures = [];
if (lock.lockfileVersion !== 3) failures.push("lockfileVersion must remain 3");
if (lock.name !== pkg.name || lock.version !== pkg.version) failures.push("lockfile root metadata does not match package.json");
if (lock.packages?.[""]?.name !== pkg.name || lock.packages?.[""]?.version !== pkg.version) failures.push("lockfile root package entry is inconsistent");
for (const [name, item] of Object.entries(lock.packages ?? {})) {
  if (!name || name === "") continue;
  if (!item || typeof item !== "object") failures.push(`${name}: malformed lock entry`);
  else {
    if (typeof item.version !== "string") failures.push(`${name}: missing version`);
    if (typeof item.resolved === "string" && !item.resolved.startsWith("https://registry.npmjs.org/")) failures.push(`${name}: dependency source is not the npm registry`);
    if (typeof item.integrity !== "string" || !/^sha512-[A-Za-z0-9+/=]+$/.test(item.integrity)) failures.push(`${name}: missing or invalid integrity hash`);
  }
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`lockfile: ${Object.keys(lock.packages ?? {}).length} package entries verified`);
}
