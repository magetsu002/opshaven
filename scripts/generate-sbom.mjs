import { promises as fs } from "node:fs";
import path from "node:path";

const lock = JSON.parse(await fs.readFile("package-lock.json", "utf8"));
const components = [];
for (const [location, item] of Object.entries(lock.packages ?? {})) {
  if (!location || location === "" || !item || typeof item !== "object" || typeof item.version !== "string") continue;
  const name = location.replace(/^node_modules\//, "");
  components.push({
    type: "library",
    name,
    version: item.version,
    purl: `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(item.version)}`,
    hashes: typeof item.integrity === "string" ? [{ alg: "SHA-512", content: item.integrity.replace(/^sha512-/, "") }] : [],
    properties: [
      { name: "opshaven:dev", value: item.dev === true ? "true" : "false" },
      ...(typeof item.resolved === "string" ? [{ name: "opshaven:resolved", value: item.resolved }] : []),
    ],
  });
}
components.sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: "urn:uuid:00000000-0000-4000-8000-000000000001",
  version: 1,
  metadata: { component: { type: "application", name: lock.name, version: lock.version, purl: `pkg:npm/${encodeURIComponent(lock.name)}@${encodeURIComponent(lock.version)}` } },
  components,
};
const output = process.argv[2] ?? "artifacts/opshaven.sbom.cdx.json";
await fs.mkdir(path.dirname(output), { recursive: true });
await fs.writeFile(output, `${JSON.stringify(sbom, null, 2)}\n`);
console.log(`sbom: ${components.length} components written to ${output}`);
