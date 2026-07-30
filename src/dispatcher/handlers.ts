import { createCoreHandlers } from "./core-handlers.js";
import { createDeploymentHandlers } from "./deployment-handlers.js";
import type { DispatcherHandlers } from "./dispatcher.js";
import { createLogHandlers } from "./log-handlers.js";
import { createMutationHandlers } from "./mutation-handlers.js";
import { createNetworkHandlers } from "./network-handlers.js";
import { createRecoveryHandlers } from "./recovery-handlers.js";

export const DISPATCHER_HANDLERS: DispatcherHandlers = Object.freeze({
  ...createCoreHandlers(),
  ...createNetworkHandlers(),
  ...createLogHandlers(),
  ...createRecoveryHandlers(),
  ...createMutationHandlers(),
  ...createDeploymentHandlers()
});
