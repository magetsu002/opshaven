#!/usr/bin/env node

import { getPackageVersion } from "./version.js";

const requested = process.argv[2];
if (requested === "--version" || requested === "-V" || requested === "version") {
  process.stdout.write(`OpsHaven MCP ${await getPackageVersion()}\n`);
} else {
  await import("./index.js");
}
