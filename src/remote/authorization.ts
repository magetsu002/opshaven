import { verify } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { decodeApprovalPayload, operationDigest, type RemoteAuthorization } from "../approval.js";
import type { OpsHavenConfig, Resource } from "../config.js";
import { OpsHavenError } from "../errors.js";
import type { ResolvedOperation } from "../policy.js";
import { ensurePrivateDirectory, readRegularFile } from "../safe-fs.js";
import type { RemoteRequest } from "./protocol.js";

function hostId(resource: Resource): string { return resource.kind === "host" ? resource.id : resource.hostId; }

export async function verifyAndConsumeRemoteAuthorization(config: OpsHavenConfig, request: RemoteRequest, authorization: RemoteAuthorization, currentState: string): Promise<string> {
  const publicKey = await readRegularFile(config.approvals.verificationPublicKeyFile, "Approval public key", { maxBytes: 65536, code: "APPROVAL_INVALID" });
  const validSignature = verify(null, Buffer.from(authorization.payload, "utf8"), publicKey, Buffer.from(authorization.signature, "base64url"));
  if (!validSignature) throw new OpsHavenError("APPROVAL_INVALID", "Remote approval signature is invalid.");
  const body = decodeApprovalPayload(authorization.payload);
  if (Date.parse(body.expiresAt) <= Date.now()) throw new OpsHavenError("APPROVAL_EXPIRED", "Remote approval has expired.");
  if (body.policyVersion !== config.policyVersion || body.expectedState !== currentState) throw new OpsHavenError("APPROVAL_INVALID", "Remote state or policy changed after approval.");
  const target = config.resources.get(request.resourceId);
  if (!target) throw new OpsHavenError("UNKNOWN_RESOURCE", "Unknown remote resource.");
  const resolved: ResolvedOperation = { operation: request.operation as ResolvedOperation["operation"], resourceId: request.resourceId, hostId: hostId(target), args: request.args, expectedState: currentState, policyVersion: config.policyVersion, mutation: true, dryRun: request.args.dryRun === true, limits: request.limits };
  if (resolved.dryRun || operationDigest(resolved) !== body.digest) throw new OpsHavenError("APPROVAL_INVALID", "Remote approval does not match the exact operation.");
  await ensurePrivateDirectory(config.approvals.remoteUsedDirectory, "Remote approval replay directory", "APPROVAL_INVALID");
  try { await fs.writeFile(path.join(config.approvals.remoteUsedDirectory, body.nonce), body.digest, { flag: "wx", mode: 0o600 }); }
  catch (error: any) {
    if (error?.code === "EEXIST") throw new OpsHavenError("APPROVAL_REPLAYED", "Remote approval was already used.");
    throw error;
  }
  return body.digest;
}
