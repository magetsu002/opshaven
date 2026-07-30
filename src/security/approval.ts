import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, open, readFile } from "node:fs/promises";
import { join } from "node:path";
import { OpsHavenError } from "../core/errors.js";
import type { ResolvedOperation } from "../policy/operations.js";
import { canonicalJson, sha256, type JsonValue } from "./canonical.js";

export type ApprovalSubject = Readonly<{
  operation: string;
  target: string;
  hostId: string;
  args: { readonly [key: string]: JsonValue };
  expectedState: { readonly [key: string]: JsonValue };
  policyVersion: string;
  expiresAt: string;
  nonce: string;
}>;

export type ApprovalRequest = Readonly<{
  version: 1;
  digest: string;
  subject: ApprovalSubject;
}>;

export type ApprovalToken = Readonly<{
  version: 1;
  digest: string;
  expiresAt: string;
  nonce: string;
  mac: string;
}>;

function operationSubject(operation: ResolvedOperation, expiresAt: string, nonce: string): ApprovalSubject {
  return {
    operation: operation.operation,
    target: operation.target,
    hostId: operation.hostId,
    args: operation.args,
    expectedState: operation.expectedState,
    policyVersion: operation.policyVersion,
    expiresAt,
    nonce
  };
}

function signingPayload(token: Omit<ApprovalToken, "mac">): string {
  return canonicalJson(token as unknown as JsonValue);
}

function hmac(payload: string, key: Uint8Array): string {
  return createHmac("sha256", key).update(payload).digest("base64url");
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function parseToken(value: unknown): ApprovalToken {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpsHavenError("APPROVAL_INVALID", "Approval token must be an object");
  }
  const token = value as Record<string, unknown>;
  const fields = Object.keys(token).sort().join(",");
  if (fields !== "digest,expiresAt,mac,nonce,version") {
    throw new OpsHavenError("APPROVAL_INVALID", "Approval token has an invalid shape");
  }
  if (
    token.version !== 1 ||
    typeof token.digest !== "string" ||
    !/^[a-f0-9]{64}$/.test(token.digest) ||
    typeof token.expiresAt !== "string" ||
    Number.isNaN(Date.parse(token.expiresAt)) ||
    typeof token.nonce !== "string" ||
    !/^[A-Za-z0-9_-]{20,100}$/.test(token.nonce) ||
    typeof token.mac !== "string" ||
    !/^[A-Za-z0-9_-]{40,100}$/.test(token.mac)
  ) {
    throw new OpsHavenError("APPROVAL_INVALID", "Approval token contains invalid fields");
  }
  return token as ApprovalToken;
}

export function createApprovalRequest(
  operation: ResolvedOperation,
  ttlSeconds: number,
  now: () => Date = () => new Date(),
  nonce: string = randomBytes(24).toString("base64url")
): ApprovalRequest {
  if (!operation.requiresApproval) {
    throw new OpsHavenError("APPROVAL_INVALID", "This operation does not require approval");
  }
  const expiresAt = new Date(now().getTime() + ttlSeconds * 1000).toISOString();
  const subject = operationSubject(operation, expiresAt, nonce);
  return { version: 1, digest: sha256(canonicalJson(subject)), subject };
}

export function signApprovalRequest(request: ApprovalRequest, key: Uint8Array): ApprovalToken {
  if (key.byteLength < 32) throw new OpsHavenError("APPROVAL_INVALID", "Approval key must contain at least 32 bytes");
  const unsigned: Omit<ApprovalToken, "mac"> = {
    version: 1,
    digest: request.digest,
    expiresAt: request.subject.expiresAt,
    nonce: request.subject.nonce
  };
  return { ...unsigned, mac: hmac(signingPayload(unsigned), key) };
}

export async function loadApprovalKey(environmentVariable: string): Promise<Uint8Array> {
  const value = process.env[environmentVariable];
  if (value === undefined || value.length < 32) {
    throw new OpsHavenError("APPROVAL_INVALID", `Approval key environment variable ${environmentVariable} is missing or short`);
  }
  return Buffer.from(value, "utf8");
}

export async function parseApprovalRequestFile(path: string): Promise<ApprovalRequest> {
  const value = JSON.parse(await readFile(path, "utf8")) as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpsHavenError("APPROVAL_INVALID", "Approval request file must contain an object");
  }
  const request = value as Record<string, unknown>;
  if (request.version !== 1 || typeof request.digest !== "string" || typeof request.subject !== "object") {
    throw new OpsHavenError("APPROVAL_INVALID", "Approval request file is invalid");
  }
  return request as ApprovalRequest;
}

export class ApprovalVerifier {
  readonly #stateDirectory: string;
  readonly #key: Uint8Array;
  readonly #now: () => Date;

  public constructor(stateDirectory: string, key: Uint8Array, now: () => Date = () => new Date()) {
    if (key.byteLength < 32) throw new OpsHavenError("APPROVAL_INVALID", "Approval key must contain at least 32 bytes");
    this.#stateDirectory = stateDirectory;
    this.#key = key;
    this.#now = now;
  }

  public async verifyAndConsume(operation: ResolvedOperation, value: unknown): Promise<ApprovalToken> {
    if (!operation.requiresApproval) throw new OpsHavenError("APPROVAL_INVALID", "Approval supplied for a non-approved operation");
    const token = parseToken(value);
    if (Date.parse(token.expiresAt) <= this.#now().getTime()) {
      throw new OpsHavenError("APPROVAL_INVALID", "Approval token has expired");
    }
    const expectedSubject = operationSubject(operation, token.expiresAt, token.nonce);
    const expectedDigest = sha256(canonicalJson(expectedSubject));
    if (!safeEqual(token.digest, expectedDigest)) {
      throw new OpsHavenError("APPROVAL_INVALID", "Approval is not bound to the exact resolved operation");
    }
    const unsigned: Omit<ApprovalToken, "mac"> = {
      version: 1,
      digest: token.digest,
      expiresAt: token.expiresAt,
      nonce: token.nonce
    };
    if (!safeEqual(token.mac, hmac(signingPayload(unsigned), this.#key))) {
      throw new OpsHavenError("APPROVAL_INVALID", "Approval signature is invalid");
    }
    await mkdir(join(this.#stateDirectory, "consumed"), { recursive: true, mode: 0o700 });
    const marker = join(this.#stateDirectory, "consumed", sha256(`${token.digest}:${token.nonce}:${token.mac}`));
    try {
      const handle = await open(marker, "wx", 0o600);
      await handle.writeFile(`${this.#now().toISOString()}\n`, "utf8");
      await handle.sync();
      await handle.close();
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new OpsHavenError("APPROVAL_REPLAYED", "Approval token has already been consumed");
      }
      throw error;
    }
    return token;
  }
}
