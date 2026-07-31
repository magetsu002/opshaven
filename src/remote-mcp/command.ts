import { McpServer } from "../mcp.js";
import type { OpsHavenConfig } from "../config.js";
import { OperationService } from "../operations.js";
import { OidcPrincipalVerifier } from "./auth.js";
import { loadRemoteMcpConfig } from "./config.js";
import { StreamableHttpServer } from "./http.js";

export interface RemoteServeFlags {
  readonly transport: string;
  readonly bindHost?: string;
  readonly port?: number;
  readonly path?: string;
  readonly unsafeAllowNonLoopback: boolean;
}

export async function runRemoteServe(config: OpsHavenConfig, configPath: string, flags: RemoteServeFlags): Promise<void> {
  if (flags.transport !== "streamable-http") throw new Error("Only --transport streamable-http is supported.");
  const remote = await loadRemoteMcpConfig(configPath, config);
  if (!remote.enabled) throw new Error("Remote MCP is disabled. Create and review the remote companion configuration before serving.");
  if (flags.bindHost !== undefined && flags.bindHost !== remote.bindHost) throw new Error("--bind cannot override the reviewed remote MCP configuration.");
  if (flags.port !== undefined && flags.port !== remote.port) throw new Error("--port cannot override the reviewed remote MCP configuration.");
  if (flags.path !== undefined && flags.path !== remote.path) throw new Error("--path cannot override the reviewed remote MCP configuration.");
  const transport = new StreamableHttpServer({
    mcp: new McpServer(new OperationService(config, undefined, configPath)),
    verifier: new OidcPrincipalVerifier(remote),
    bindHost: remote.bindHost,
    port: remote.port,
    path: remote.path,
    unsafeAllowNonLoopback: flags.unsafeAllowNonLoopback,
    maxBodyBytes: remote.requests.maximumBodyBytes,
  });
  const started = await transport.start();
  process.stdout.write(`${JSON.stringify({ ok: true, transport: "streamable-http", url: started.url, authentication: "oidc-bearer", remoteCapability: "read-only" })}\n`);
  await new Promise<void>((resolve) => {
    let closing = false;
    const close = (): void => {
      if (closing) return;
      closing = true;
      void transport.close().finally(resolve);
    };
    process.on("SIGINT", close);
    process.on("SIGTERM", close);
  });
}
