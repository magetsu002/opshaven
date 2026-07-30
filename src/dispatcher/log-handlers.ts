import { OpsHavenError } from "../core/errors.js";
import { redactText } from "../security/redaction.js";
import type { DispatcherHandlers } from "./dispatcher.js";
import {
  assertArgs,
  assertTarget,
  DEFAULT_RUNTIME,
  findResource,
  fixedCommand,
  type HandlerRuntime
} from "./runtime.js";

const WINDOWS: Readonly<Record<string, string>> = Object.freeze({
  "15m": "-15 minutes",
  "1h": "-1 hour",
  "24h": "-24 hours"
});

export function createLogHandlers(runtime: HandlerRuntime = DEFAULT_RUNTIME): DispatcherHandlers {
  return {
    get_redacted_logs: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["serviceId", "lines", "window"]);
      const service = findResource(config.services, request.args.serviceId, dispatcherHostId, "service");
      assertTarget(request, service.id);
      const lines = request.args.lines;
      const window = request.args.window;
      if (typeof lines !== "number" || !Number.isInteger(lines) || lines < 1 || lines > 500) {
        throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Log line count must be from 1 to 500");
      }
      if (typeof window !== "string" || WINDOWS[window] === undefined) {
        throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Log window is not allowlisted");
      }
      const result = await fixedCommand(runtime, request, "/usr/bin/journalctl", [
        "-u",
        service.unit,
        "--no-pager",
        "--output=short-iso",
        "--lines",
        String(lines),
        "--since",
        WINDOWS[window]
      ]);
      const redacted = redactText(result.stdout, config.secrets)
        .split("\n")
        .slice(0, lines)
        .join("\n");
      return {
        serviceId: service.id,
        window,
        requestedLines: lines,
        returnedLines: redacted.length === 0 ? 0 : redacted.split("\n").length,
        logs: redacted,
        redacted: true
      };
    }
  };
}
