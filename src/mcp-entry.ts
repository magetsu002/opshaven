#!/usr/bin/env node

const requested = process.argv[2];
if (requested === "--version" || requested === "-V" || requested === "version") {
  process.stdout.write(`OpsHaven MCP ${process.env.npm_package_version ?? "1.0.0"}\n`);
} else {
  await import("./index.js");
}
