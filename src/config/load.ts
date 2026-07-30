import { readFile } from "node:fs/promises";
import { OpsHavenError, errorMessage } from "../core/errors.js";
import { parseConfig, type OpsHavenConfig } from "./schema.js";

export async function loadConfig(path: string): Promise<OpsHavenConfig> {
  let text: string;
  try {
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
