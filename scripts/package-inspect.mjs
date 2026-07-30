import { promises as fs } from "node:fs";

const pkg = JSON.parse(await fs.readFile("package.json", "utf8"));
const expectedBins = {
  opshaven: "dist/src/cli.js",
  "opshaven-mcp": "dist/src/index.js",
  "opshaven-dispatcher": "dist/src/remote/dispatcher.js",
};
const failures = [];
if (pkg.name !== "opshaven") failures.push("package name must be opshaven");
if (pkg.version !== "1.0.0") failures.push("package version must be 1.0.0");
if (pkg.license !== "MIT") failures.push("package license must be MIT");
if (pkg.type !== "module") failures.push("package type must be module");
if (pkg.engines?.node !== ">=22.0.0") failures.push("Node engine must remain >=22.0.0");
if (JSON.stringify(pkg.bin) !== JSON.stringify(expectedBins)) failures.push("package binaries do not match the supported entrypoints");
for (const [name, file] of Object.entries(expectedBins)) {
  const stat = await fs.stat(file).catch(() => null);
  if (!stat?.isFile()) failures.push(`${name}: built entrypoint is missing`);
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log("package: metadata and built entrypoints verified");
}
