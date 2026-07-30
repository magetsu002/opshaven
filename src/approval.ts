import { createHmac, randomBytes, sign, timingSafeEqual } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { canonicalize, sha256 } from "./canonical.js";
import type { ApprovalConfig } from "./config.js";
import { OpsHavenError } from "./errors.js";
import type { ResolvedOperation } from "./policy.js";
import { ensurePrivateDirectory, readRegularFile, readRegularTextFile } from "./safe-fs.js";

export interface ApprovalPayload { version: 1; nonce: string; digest: string; expectedState: string; policyVersion: string; expiresAt: string }
export interface RemoteAuthorization { payload: string; signature: string }

export function encodeApprovalPayload(value: ApprovalPayload): string { return Buffer.from(canonicalize(value), "utf8").toString("base64url"); }
export function decodeApprovalPayload(value: string): ApprovalPayload {
  let item: unknown;
  try { item = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown; }
  catch { throw new OpsHavenError("APPROVAL_INVALID", "Approval token is malformed."); }
  if (!item || typeof item !== "object" || Array.isArray(item)) throw new OpsHavenError("APPROVAL_INVALID", "Approval token is malformed.");
  const body = item as Record<string, unknown>;
  if (body.version !== 1 || typeof body.nonce !== "string" || !/^[a-f0-9]{32}$/.test(body.nonce) || typeof body.digest !== "string" || !/^[a-f0-9]{64}$/.test(body.digest) || typeof body.expectedState !== "string" || !/^[a-f0-9]{64}$/.test(body.expectedState) || typeof body.policyVersion !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(body.policyVersion) || typeof body.expiresAt !== "string" || !Number.isFinite(Date.parse(body.expiresAt))) throw new OpsHavenError("APPROVAL_INVALID", "Approval token is malformed.");
  return body as unknown as ApprovalPayload;
}

export function operationDigest(operation: ResolvedOperation): string {
  return sha256({ operation: operation.operation, resourceId: operation.resourceId, hostId: operation.hostId, args: operation.args, expectedState: operation.expectedState, policyVersion: operation.policyVersion, mutation: operation.mutation, dryRun: operation.dryRun, limits: operation.limits });
}

export class ApprovalService {
  constructor(private readonly config: ApprovalConfig) {}

  private pendingDirectory(): string { return path.join(this.config.directory, "pending"); }
  private usedDirectory(): string { return path.join(this.config.directory, "used"); }
  private async ensureDirectories(): Promise<void> {
    await ensurePrivateDirectory(this.config.directory, "Approval directory", "APPROVAL_INVALID");
    await ensurePrivateDirectory(this.pendingDirectory(), "Pending approval directory", "APPROVAL_INVALID");
    await ensurePrivateDirectory(this.usedDirectory(), "Used approval directory", "APPROVAL_INVALID");
  }
  private async secret(): Promise<Uint8Array> {
    const value = await readRegularFile(this.config.secretFile, "Approval secret", { ownerOnly: true, maxBytes: 65536, code: "APPROVAL_INVALID" });
    if (value.length < 32) throw new OpsHavenError("APPROVAL_INVALID", "Approval secret is too short.");
    return value;
  }

  async create(operation: ResolvedOperation, ttlSeconds = this.config.defaultTtlSeconds): Promise<{ token: string; digest: string; expiresAt: string }> {
    if (!operation.mutation || operation.dryRun || operation.expectedState === "unresolved") throw new OpsHavenError("APPROVAL_INVALID", "Only fully resolved non-dry-run mutations can be approved.");
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 3600) throw new OpsHavenError("APPROVAL_INVALID", "Approval TTL is invalid.");
    await this.ensureDirectories();
    const digest = operationDigest(operation);
    const body: ApprovalPayload = { version: 1, nonce: randomBytes(16).toString("hex"), digest, expectedState: operation.expectedState, policyVersion: operation.policyVersion, expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString() };
    const encoded = encodeApprovalPayload(body);
    const localSignature = createHmac("sha256", await this.secret()).update(encoded).digest("base64url") as string;
    const privateKey = await readRegularFile(this.config.signingPrivateKeyFile, "Approval signing key", { ownerOnly: true, maxBytes: 65536, code: "APPROVAL_INVALID" });
    const remoteSignature = sign(null, Buffer.from(encoded, "utf8"), privateKey).toString("base64url");
    await fs.writeFile(path.join(this.pendingDirectory(), body.nonce), canonicalize(body), { flag: "wx", mode: 0o600 });
    return { token: `${encoded}.${localSignature}.${remoteSignature}`, digest, expiresAt: body.expiresAt };
  }

  async consume(token: string, operation: ResolvedOperation): Promise<{ digest: string; authorization: RemoteAuthorization }> {
    const [encoded, localSignature, remoteSignature, extra] = token.split(".");
    if (!encoded || !localSignature || !remoteSignature || extra) throw new OpsHavenError("APPROVAL_INVALID", "Approval token is malformed.");
    const expectedSignature = createHmac("sha256", await this.secret()).update(encoded).digest("base64url") as string;
    const actualBytes = Buffer.from(localSignature, "utf8");
    const expectedBytes = Buffer.from(expectedSignature, "utf8");
    if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) throw new OpsHavenError("APPROVAL_INVALID", "Approval signature is invalid.");
    const body = decodeApprovalPayload(encoded);
    if (Date.parse(body.expiresAt) <= Date.now()) throw new OpsHavenError("APPROVAL_EXPIRED", "Approval has expired.");
    const digest = operationDigest(operation);
    if (body.digest !== digest || body.expectedState !== operation.expectedState || body.policyVersion !== operation.policyVersion) throw new OpsHavenError("APPROVAL_INVALID", "Approval does not match the exact resolved operation.");
    await this.ensureDirectories();
    const pending = path.join(this.pendingDirectory(), body.nonce);
    const used = path.join(this.usedDirectory(), body.nonce);
    const pendingBody = await readRegularTextFile(pending, "Pending approval", { ownerOnly: true, maxBytes: 4096, code: "APPROVAL_INVALID" }).catch((error: unknown) => {
      if (error instanceof OpsHavenError) throw new OpsHavenError("APPROVAL_REPLAYED", "Approval was already used or revoked.");
      throw error;
    });
    if (pendingBody !== canonicalize(body)) throw new OpsHavenError("APPROVAL_INVALID", "Pending approval state does not match the signed token.");
    try { await fs.rename(pending, used); }
    catch (error: any) {
      if (error?.code === "ENOENT" || error?.code === "EEXIST") throw new OpsHavenError("APPROVAL_REPLAYED", "Approval was already used or revoked.");
      throw error;
    }
    return { digest, authorization: { payload: encoded, signature: remoteSignature } };
  }
}
