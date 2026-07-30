import { loadConfig } from "../../dist/src/config.js";
import { OperationService } from "../../dist/src/operations.js";

const [configPath] = process.argv.slice(2);
if (!configPath) throw new Error("Usage: inspect.mjs <config>");
const config = await loadConfig(configPath);
const result = await new OperationService(config, undefined, configPath).execute(
  "get_host_summary",
  { resourceId: "host.fixture" },
  undefined,
  "integration-client",
);
process.stdout.write(`${JSON.stringify(result)}\n`);
