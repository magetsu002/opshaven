import { constants as fsConstants, promises as fs } from "node:fs";

const pkg = JSON.parse(await fs.readFile("package.json", "utf8"));
const expectedBins = {
  opshaven: "dist/src/cli-entry.js",
  "opshaven-mcp": "dist/src/mcp-entry.js",
  "opshaven-dispatcher": "dist/src/remote/dispatcher.js",
  "opshaven-readonly-dispatcher": "dist-readonly/src/remote/read-only-dispatcher.js",
};
const failures = [];
const noFollow = fsConstants.O_NOFOLLOW ?? 0;
if (pkg.name !== "opshaven") failures.push("package name must be opshaven");
if (pkg.version !== "1.0.0") failures.push("package version must be 1.0.0");
if (pkg.license !== "MIT") failures.push("package license must be MIT");
if (pkg.type !== "module") failures.push("package type must be module");
if (pkg.engines?.node !== ">=22.0.0") failures.push("Node engine must remain >=22.0.0");
if (JSON.stringify(pkg.bin) !== JSON.stringify(expectedBins)) failures.push("package binaries do not match the supported entrypoints");
for (const [name, file] of Object.entries(expectedBins)) {
  const handle = await fs.open(file, fsConstants.O_RDONLY | noFollow).catch(() => null);
  if (!handle) {
    failures.push(`${name}: built entrypoint is missing or unsafe`);
    continue;
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) failures.push(`${name}: built entrypoint is missing or unsafe`);
    else if ((stat.mode & 0o111) === 0) failures.push(`${name}: built entrypoint is not executable`);
    const source = await handle.readFile("utf8");
    if (!source.startsWith("#!/usr/bin/env node\n")) failures.push(`${name}: built entrypoint has no supported Node.js shebang`);
  } finally {
    await handle.close();
  }
}
if (pkg.scripts?.cli !== "node dist/src/cli-entry.js") failures.push("human CLI script must use cli-entry.js");
if (pkg.scripts?.["dev:cli"] !== "npm run build && node dist/src/cli-entry.js") failures.push("development CLI script must build and use cli-entry.js");
if (pkg.scripts?.["install:local"] !== "npm run build && npm link") failures.push("local installation script must build before linking the CLI");
if (pkg.scripts?.mcp !== "node dist/src/mcp-entry.js") failures.push("MCP script must use mcp-entry.js");
if (pkg.scripts?.["install:check"] !== "bash scripts/check-installed-cli.sh") failures.push("installed CLI lifecycle check is missing");
if (pkg.scripts?.start !== "npm run cli -- help") failures.push("npm start must show human CLI help");
const isolatedFiles = [
  "src/remote/read-only-dispatcher.ts",
  "src/remote/read-only-protocol.ts",
  "src/remote/read-only-policy.ts",
  "src/remote/read-only-handlers.ts",
];
const forbidden = [
  /from\s+["'][^"']*(?:mutations|authorization|approval)[^"']*["']/i,
  /\b(?:handleMutation|verifyAndConsumeRemoteAuthorization|ApprovalService)\b/,
  /\/usr\/(?:bin|sbin)\/(?:sudo|docker)\b/,
  /docker\.sock/i,
];
for (const file of isolatedFiles) {
  const source = await fs.readFile(file, "utf8");
  for (const pattern of forbidden) {
    if (pattern.test(source)) failures.push(`${file}: read-only target imports a privileged capability`);
  }
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log("package: human CLI, local installation, protocol server, isolated target, and executable entrypoints verified");
}
