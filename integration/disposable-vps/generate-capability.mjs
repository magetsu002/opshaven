import { promises as fs } from "node:fs";
import {
  buildCapabilityPayload,
  dispatcherArtifactSha256,
  signCapabilityManifest,
} from "../../dist/src/capabilities.js";
import {
  buildDeclarationBinding,
  capabilityDeclarationHash,
  loadCapabilityDeclaration,
  signDeclarationBinding,
} from "../../dist/src/capability-declaration.js";
import { loadConfig } from "../../dist/src/config.js";

const [configPath, privateKeyPath, dispatcherPath, declarationPath, capabilityOutput, bindingOutput] = process.argv.slice(2);
if (!configPath || !privateKeyPath || !dispatcherPath || !declarationPath || !capabilityOutput || !bindingOutput) {
  throw new Error("Capability fixture arguments are incomplete.");
}
const config = await loadConfig(configPath);
const privateKey = await fs.readFile(privateKeyPath);
const dispatcherSha256 = await dispatcherArtifactSha256(dispatcherPath);
const declaration = await loadCapabilityDeclaration(declarationPath);
const expiresAt = new Date(Date.now() + 3600000).toISOString();
const full = buildCapabilityPayload(config, "controlled", dispatcherSha256, expiresAt);
const allowedOperations = full.allowedOperations.filter((operation) => (full.allowedResources[operation] ?? []).length > 0);
const allowedResources = Object.fromEntries(allowedOperations.map((operation) => [operation, full.allowedResources[operation]]));
await fs.writeFile(capabilityOutput, `${JSON.stringify(signCapabilityManifest({ ...full, allowedOperations, allowedResources }, privateKey))}\n`, { mode: 0o600 });
const declarationBinding = buildDeclarationBinding(
  config,
  "controlled",
  dispatcherSha256,
  capabilityDeclarationHash(declaration),
  expiresAt,
);
await fs.writeFile(bindingOutput, `${JSON.stringify(signDeclarationBinding(declarationBinding, privateKey))}\n`, { mode: 0o600 });
