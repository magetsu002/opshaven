import { OpsHavenError } from "../core/errors.js";
import type { DispatcherHandlers } from "./dispatcher.js";
import {
  assertArgs,
  assertTarget,
  DEFAULT_RUNTIME,
  findResource,
  fixedCommand,
  type HandlerRuntime
} from "./runtime.js";

function expectedActiveState(request: Parameters<NonNullable<DispatcherHandlers["restart_service"]>>[0]): string {
  const fields = Object.keys(request.expectedState);
  if (fields.length !== 1 || fields[0] !== "activeState") {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Restart expected state must contain only activeState");
  }
  const expected = request.expectedState.activeState;
  if (typeof expected !== "string" || !["active", "inactive", "failed"].includes(expected)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Restart expected active state is invalid");
  }
  return expected;
}

export function createMutationHandlers(runtime: HandlerRuntime = DEFAULT_RUNTIME): DispatcherHandlers {
  return {
    restart_service: async (request, config, dispatcherHostId) => {
      assertArgs(request, ["serviceId"]);
      const service = findResource(config.services, request.args.serviceId, dispatcherHostId, "service");
      assertTarget(request, service.id);
      if (!service.restartAllowed) {
        throw new OpsHavenError("POLICY_DENIED", "Restart is disabled for this configured service");
      }
      const expected = expectedActiveState(request);
      const current = await fixedCommand(runtime, request, "/usr/bin/systemctl", ["is-active", service.unit], {
        allowExitCodes: [0, 3, 4]
      });
      const currentState = current.stdout || "unknown";
      if (currentState !== expected) {
        throw new OpsHavenError("POLICY_DENIED", "Service state changed since approval was resolved", {
          expected,
          observed: currentState
        });
      }
      if (request.dryRun) {
        return {
          serviceId: service.id,
          dryRun: true,
          wouldRestartUnit: service.unit,
          observedState: currentState,
          changed: false
        };
      }
      await fixedCommand(runtime, request, "/usr/bin/sudo", ["-n", "/usr/bin/systemctl", "restart", service.unit]);
      const verified = await fixedCommand(runtime, request, "/usr/bin/systemctl", ["is-active", service.unit], {
        allowExitCodes: [0, 3, 4]
      });
      if (verified.exitCode !== 0 || verified.stdout !== "active") {
        throw new OpsHavenError("OPERATION_FAILED", "Service did not become active after restart", {
          observed: verified.stdout || "unknown"
        });
      }
      return {
        serviceId: service.id,
        unit: service.unit,
        previousState: currentState,
        activeState: verified.stdout,
        changed: true
      };
    }
  };
}
