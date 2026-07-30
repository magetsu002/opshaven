import { sha256 } from "../canonical.js";
import type { DeploymentResource, OpsHavenConfig, Resource, ServiceResource } from "../config.js";
import { OpsHavenError } from "../errors.js";
import type { RemoteRequest } from "./protocol.js";
import { verifyAndConsumeRemoteAuthorization } from "./authorization.js";
import { DeploymentManager } from "./deployment.js";
import { handleInspection } from "./handlers.js";
import type { CommandRunner } from "./runner.js";
import { requireSuccess } from "./runner.js";

export interface MutationContext { config: OpsHavenConfig; runner: CommandRunner }
function resource<T extends Resource["kind"]>(context: MutationContext, request: RemoteRequest, kind: T): Extract<Resource, { kind: T }> {
  const found = context.config.resources.get(request.resourceId);
  if (!found || found.kind !== kind) throw new OpsHavenError("UNKNOWN_RESOURCE", "Unknown mutation resource.");
  return found as Extract<Resource, { kind: T }>;
}
async function currentState(context: MutationContext, request: RemoteRequest): Promise<string> {
  const { authorization: _authorization, ...baseRequest } = request;
  const data = await handleInspection(context, { ...baseRequest, operation: "get_state_fingerprint" });
  return sha256(data);
}
async function authorize(context: MutationContext, request: RemoteRequest): Promise<string> {
  if (!request.authorization) throw new OpsHavenError("APPROVAL_REQUIRED", "Remote mutation approval is required.");
  return await verifyAndConsumeRemoteAuthorization(context.config, request, request.authorization, await currentState(context, request));
}

export async function handleMutation(context: MutationContext, request: RemoteRequest): Promise<Record<string, unknown>> {
  if (request.operation === "restart_service") {
    const target = resource(context, request, "service") as ServiceResource;
    if (request.args.dryRun === true) return { dryRun: true, changed: false, plan: { resourceId: target.id, action: "restart" } };
    const approvalDigest = await authorize(context, request);
    await requireSuccess(context.runner, "/usr/bin/sudo", ["--non-interactive", "/usr/bin/systemctl", "restart", target.unit], { ...request.limits });
    const { authorization: _authorization, ...baseRequest } = request;
    const status = await handleInspection(context, { ...baseRequest, operation: "get_service_status" });
    return { dryRun: false, changed: true, approvalDigest, status };
  }
  if (request.operation === "deploy_commit" || request.operation === "rollback_deployment") {
    const target = resource(context, request, "deployment") as DeploymentResource;
    if (request.args.dryRun !== true) await authorize(context, request);
    const manager = new DeploymentManager(context.config, context.runner);
    return request.operation === "deploy_commit" ? await manager.deploy(target, request.args, request.limits) : await manager.rollback(target, request.args, request.limits);
  }
  throw new OpsHavenError("UNKNOWN_OPERATION", "Unknown remote mutation operation.");
}
