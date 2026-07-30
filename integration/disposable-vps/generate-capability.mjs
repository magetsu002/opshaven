import { promises as fs } from "node:fs";
import {
  buildCapabilityPayload,
  dispatcherArtifactSha256,
  signCapabilityManifest,
} from "../../dist/src/capabilities.js";
import { loadConfig } from "../../dist/src/config.js";

const [configPath, privateKeyPath, dispatcherPath, ...outputs] = process.argv.slice(2);
if (!configPath || !privateKeyPath || !dispatcherPath || outputs.length === 0) {
  throw new Error("Capability fixture arguments are incomplete.");
}
const config = await loadConfig(configPath);
const full = buildCapabilityPayload(
  config,
  "controlled",
  await dispatcherArtifactSha256(dispatcherPath),
  new Date(Date.now() + 3600000).toISOString(),
);
const allowedOperations = full.allowedOperations.filter(
  (operation) => (full.allowedResources[operation] ?? []).length > 0,
);
const allowedResources = Object.fromEntries(
  allowedOperations.map((operation) => [operation, full.allowedResources[operation]]),
);
const payload = { ...full, allowedOperations, allowedResources };
const privateKey = await fs.readFile(privateKeyPath);
const signed = signCapabilityManifest(payload, privateKey);
for (const output of outputs) {
  await fs.writeFile(output, `${JSON.stringify(signed)}\n`, { mode: 0o600 });
}
