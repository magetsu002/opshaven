import type { VerifiedCapability } from "../capabilities.js";
import type { McpPrincipal } from "../mcp.js";
import { REMOTE_READ_ONLY_TOOLS } from "./config.js";
import type { HttpRequestIdentity, PrincipalVerifier } from "./http.js";

export class CapabilityBoundPrincipalVerifier implements PrincipalVerifier {
  constructor(private readonly verifier: PrincipalVerifier, private readonly capability: VerifiedCapability) {
    if (capability.payload.mode !== "read-only") throw new Error("Remote MCP requires a signed read-only capability.");
  }

  async verify(identity: HttpRequestIdentity): Promise<McpPrincipal> {
    const principal = await this.verifier.verify(identity);
    const profileTools = principal.allowedTools ?? new Set<string>();
    const capabilityTools = new Set<string>(this.capability.payload.allowedOperations);
    const tools = [...profileTools].filter((tool) => REMOTE_READ_ONLY_TOOLS.has(tool) && capabilityTools.has(tool)).sort();
    const resourcesByTool = new Map<string, ReadonlySet<string>>();
    const profileResources = principal.allowedResources ?? new Set<string>();
    for (const tool of tools) {
      const capabilityResources = new Set(this.capability.payload.allowedResources[tool] ?? []);
      resourcesByTool.set(tool, new Set([...profileResources].filter((resource) => capabilityResources.has(resource))));
    }
    return Object.freeze({
      ...principal,
      allowedTools: new Set(tools),
      allowedResourcesByTool: resourcesByTool,
    });
  }
}
