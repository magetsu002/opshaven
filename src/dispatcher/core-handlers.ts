import type { ServiceConfig } from "../config/schema.js";
import { OpsHavenError } from "../core/errors.js";
import type { JsonValue } from "../security/canonical.js";
import type { DispatcherHandlers } from "./dispatcher.js";
import {
  assertArgs,
  assertTarget,
  DEFAULT_RUNTIME,
  findResource,
  fixedCommand,
  type HandlerRuntime
} from "./runtime.js";

function parseSystemdShow(text: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (["Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID"].includes(key)) {
      result[key] = value;
    }
  }
  return result;
}

async function environmentKeys(
  runtime: HandlerRuntime,
  request: Parameters<NonNullable<DispatcherHandlers["get_runtime_config_status"]>>[0],
  service: ServiceConfig
): Promise<readonly string[]> {
  if (service.runtimeEnvFile === undefined) return [];
  const result = await fixedCommand(
    runtime,
    request,
    "/usr/bin/grep",
    ["-oE", "^[A-Za-z_][A-Za-z0-9_]*=", service.runtimeEnvFile],
    { allowExitCodes: [0, 1] }
  );
  return result.stdout
    .split("\n")
    .map((line) => line.replace(/=$/, ""))
    .filter((line) => line.length > 0)
    .filter((line, index, values) => values.indexOf(line) === index)
    .sort();
}

export function createCoreHandlers(runtime: HandlerRuntime = DEFAULT_RUNTIME): DispatcherHandlers {
  return {
    get_host_summary: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["hostId"]);
      if (request.args.hostId !== dispatcherHostId) {
        throw new OpsHavenError("RESOURCE_NOT_FOUND", "Host is not served by this dispatcher");
      }
      assertTarget(request, dispatcherHostId);
      const kernel = await fixedCommand(runtime, request, "/usr/bin/uname", ["-srm"]);
      const uptime = await fixedCommand(runtime, request, "/usr/bin/uptime", ["-p"]);
      return { hostId: dispatcherHostId, kernel: kernel.stdout, uptime: uptime.stdout };
    },

    get_deployed_commit: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["deploymentId"]);
      const deployment = findResource(config.deployments, request.args.deploymentId, dispatcherHostId, "deployment");
      assertTarget(request, deployment.id);
      const commit = await fixedCommand(runtime, request, "/usr/bin/git", [
        "-C",
        deployment.repositoryPath,
        "rev-parse",
        "HEAD"
      ]);
      if (!/^[a-f0-9]{40}$/.test(commit.stdout)) {
        throw new OpsHavenError("OPERATION_FAILED", "Repository HEAD is not a full Git commit SHA");
      }
      return { deploymentId: deployment.id, commit: commit.stdout };
    },

    get_service_status: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["serviceId"]);
      const service = findResource(config.services, request.args.serviceId, dispatcherHostId, "service");
      assertTarget(request, service.id);
      const status = await fixedCommand(runtime, request, "/usr/bin/systemctl", [
        "show",
        service.unit,
        "--no-page",
        "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID"
      ]);
      return { serviceId: service.id, unit: service.unit, status: parseSystemdShow(status.stdout) };
    },

    get_container_status: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["containerId"]);
      const container = findResource(config.containers, request.args.containerId, dispatcherHostId, "container");
      assertTarget(request, container.id);
      const state = await fixedCommand(runtime, request, "/usr/bin/docker", [
        "inspect",
        "--format",
        "{{json .State}}",
        container.containerName
      ]);
      let parsed: JsonValue;
      try {
        parsed = JSON.parse(state.stdout) as JsonValue;
      } catch {
        throw new OpsHavenError("OPERATION_FAILED", "Docker returned malformed state JSON");
      }
      return { containerId: container.id, engine: container.engine, state: parsed };
    },

    get_runtime_config_status: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["serviceId"]);
      const service = findResource(config.services, request.args.serviceId, dispatcherHostId, "service");
      assertTarget(request, service.id);
      const present = await environmentKeys(runtime, request, service);
      const presentSet = new Set(present);
      return {
        serviceId: service.id,
        configured: service.runtimeEnvFile !== undefined,
        required: service.requiredEnvironment.map((name) => ({ name, present: presentSet.has(name) })),
        valuesExposed: false
      };
    }
  };
}
