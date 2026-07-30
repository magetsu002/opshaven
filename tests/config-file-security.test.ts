import assert from "node:assert/strict";
import test from "node:test";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { loadConfig } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";

async function root(): Promise<string> { return await fs.mkdtemp(path.join(tmpdir(), "opshaven-config-file-")); }

test("configuration loader rejects malformed JSON with a typed failure", async () => {
  const file = path.join(await root(), "config.json");
  await fs.writeFile(file, "{");
  await assert.rejects(loadConfig(file), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
});

test("configuration loader rejects oversized files before parsing", async () => {
  const file = path.join(await root(), "config.json");
  await fs.writeFile(file, "x".repeat(1048577));
  await assert.rejects(loadConfig(file), (error: unknown) => error instanceof OpsHavenError && error.code === "CONFIG_INVALID");
});
