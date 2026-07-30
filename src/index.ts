#!/usr/bin/env node
import { VERSION } from "./version.js";

export function startupBanner(): string {
  return `OpsHaven MCP ${VERSION}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.stderr.write(`${startupBanner()}\n`);
}
