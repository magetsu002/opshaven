import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

let cachedVersion: Promise<string> | undefined;

async function readPackageVersion(): Promise<string> {
  const packagePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../package.json");
  const parsed = JSON.parse(await fs.readFile(packagePath, "utf8")) as Record<string, unknown>;
  if (typeof parsed.version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(parsed.version)) {
    throw new Error("OpsHaven package version is invalid.");
  }
  return parsed.version;
}

export async function getPackageVersion(): Promise<string> {
  cachedVersion ??= readPackageVersion();
  return await cachedVersion;
}
