import { McpServer } from "../mcp.js";
import type { OpsHavenConfig } from "../config.js";
import { OperationService } from "../operations.js";
import { RejectAllVerifier, StreamableHttpServer } from "./http.js";

export interface RemoteServeFlags {
  readonly transport: string;
  readonly bindHost?: string;
  readonly port?: number;
  readonly path?: string;
  readonly unsafeAllowNonLoopback: boolean;
}

export async function runRemoteServe(config: OpsHavenConfig, configPath: string, flags: RemoteServeFlags): Promise<void> {
  if (flags.transport !== "streamable-http") throw new Error("Only --transport streamable-http is supported.");
  const transport = new StreamableHttpServer({
    mcp: new McpServer(new OperationService(config, undefined, configPath)),
    verifier: new RejectAllVerifier(),
    ...(flags.bindHost ? { bindHost: flags.bindHost } : {}),
    ...(flags.port !== undefined ? { port: flags.port } : {}),
    ...(flags.path ? { path: flags.path } : {}),
    unsafeAllowNonLoopback: flags.unsafeAllowNonLoopback,
  });
  const started = await transport.start();
  process.stdout.write(`${JSON.stringify({ ok: true, transport: "streamable-http", url: started.url, authentication: "required-unconfigured" })}\n`);
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
