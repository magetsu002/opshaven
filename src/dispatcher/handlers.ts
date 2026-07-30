import { createCoreHandlers } from "./core-handlers.js";
import type { DispatcherHandlers } from "./dispatcher.js";
import { createNetworkHandlers } from "./network-handlers.js";

export const DISPATCHER_HANDLERS: DispatcherHandlers = Object.freeze({
  ...createCoreHandlers(),
  ...createNetworkHandlers()
});
