import { lstat, readFile } from "node:fs/promises";
import { OpsHavenError, errorMessage } from "../core/errors.js";
import { parseConfig, type OpsHavenConfig } from "./schema.js";

export async function loadConfig(path: string): Promise<OpsHavenConfig> {
  let text: string;
  try {
    if (!path.startsWith("/")) throw new OpsHavenError("CONFIG_INVALID", "Configuration path must be absolute");
    const info = await lstat(path);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new OpsHavenError("CONFIG_INVALID", "Configuration path must be a non-symlink regular file");
    }
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new OpsHavenError("CONFIG_INVALID", `Unable to read configuration: ${errorMessage(error)}`);
  }
  try {
    return parseConfig(JSON.parse(text) as unknown);
  } catch (error) {
    if (error instanceof OpsHavenError) throw error;
    throw new OpsHavenError("CONFIG_INVALID", `Configuration is not valid JSON: ${errorMessage(error)}`);
  }
}
