import { randomBytes, sign, verify } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import {
  capabilityManifestPath,
  parseCapabilityPayload,
  parseSignedCapabilityManifest,
  verifyCapabilityManifest,
  type CapabilityMode,
  type VerifiedCapability,
} from "../capabilities.js";
import { canonicalize, sha256 } from "../canonical.js";
import type { OpsHavenConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { ensurePrivateDirectory, readRegularFile, readRegularTextFile } from "../safe-fs.js";
import { parseRemoteResponse, type RemoteRequest, type RemoteResponse } from "./protocol.js";

export interface AuthenticatedRequestPayload {
  version: 2;
  request: RemoteRequest;
  capabilityHash: string;
  dispatcherSha256: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export interface AuthenticatedRequestEnvelope {
  version: 2;
  payload: string;
  signature: string;
}

export interface AuthenticatedResponsePayload {
  version: 2;
  requestHash: string;
  resultHash: string;
  activeCapabilityHash: string;
  dispatcherSha256: string;
  timestamp: string;
  response: RemoteResponse;
}

export interface AuthenticatedResponseEnvelope {
  version: 2;
  payload: string;
  signature: string;
}

export interface ClientProtocolContext {
  capability: VerifiedCapability;
  requestPrivateKey: Uint8Array;
  responsePublicKey: Uint8Array;
}

const ENCODED = /^[A-Za-z0-9_-]{1,524288}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const NONCE = /^[a-f0-9]{32}$/;

function plain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const allowed = new Set(expected);
  if (Object.keys(value).some((key) => !allowed.has(key)) || expected.some((key) => !(key in value))) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `${label} has an incompatible schema.`);
  }
}

function encode(value: unknown): string {
  return Buffer.from(canonicalize(value), "utf8").toString("base64url");
}

function decodeCanonicalBytes(encoded: string, label: string): Uint8Array {
  const decoded = Buffer.from(encoded, "base64url");
  if (Buffer.from(decoded).toString("base64url") !== encoded) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `${label} is not canonically encoded.`);
  }
  return decoded;
}

function decode(encoded: string, label: string): unknown {
  try {
    return JSON.parse(Buffer.from(decodeCanonicalBytes(encoded, `${label} payload`)).toString("utf8")) as unknown;
  } catch (error) {
    if (error instanceof OpsHavenError) throw error;
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `${label} payload is malformed.`);
  }
}

function parseSignedEnvelope(value: unknown, label: string): { payload: string; signature: string } {
  if (!plain(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `${label} is malformed.`);
  exactKeys(value, ["version", "payload", "signature"], label);
  if (
    value.version !== 2
    || typeof value.payload !== "string"
    || typeof value.signature !== "string"
    || !ENCODED.test(value.payload)
    || !ENCODED.test(value.signature)
  ) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `${label} is malformed.`);
  }
  decodeCanonicalBytes(value.payload, `${label} payload`);
  const signature = decodeCanonicalBytes(value.signature, `${label} signature`);
  if (signature.length !== 64) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `${label} signature has an invalid length.`);
  return { payload: value.payload, signature: value.signature };
}

function verifyEnvelopeSignature(encoded: string, signature: string, publicKey: Uint8Array, label: string): void {
  const decodedSignature = decodeCanonicalBytes(signature, `${label} signature`);
  if (!verify(null, Buffer.from(encoded, "utf8"), publicKey, decodedSignature)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", `${label} signature is invalid.`);
  }
}

function parseRequestPayload(value: unknown): AuthenticatedRequestPayload {
  if (!plain(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated request payload is malformed.");
  exactKeys(value, ["version", "request", "capabilityHash", "dispatcherSha256", "nonce", "issuedAt", "expiresAt"], "Authenticated request payload");
  if (
    value.version !== 2
    || !plain(value.request)
    || typeof value.capabilityHash !== "string"
    || !SHA256.test(value.capabilityHash)
    || typeof value.dispatcherSha256 !== "string"
    || !SHA256.test(value.dispatcherSha256)
    || typeof value.nonce !== "string"
    || !NONCE.test(value.nonce)
    || typeof value.issuedAt !== "string"
    || typeof value.expiresAt !== "string"
    || !Number.isFinite(Date.parse(value.issuedAt))
    || !Number.isFinite(Date.parse(value.expiresAt))
  ) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated request payload is malformed.");
  }
  return value as unknown as AuthenticatedRequestPayload;
}

function parseResponsePayload(value: unknown): AuthenticatedResponsePayload {
  if (!plain(value)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated response payload is malformed.");
  exactKeys(value, ["version", "requestHash", "resultHash", "activeCapabilityHash", "dispatcherSha256", "timestamp", "response"], "Authenticated response payload");
  if (
    value.version !== 2
    || typeof value.requestHash !== "string"
    || !SHA256.test(value.requestHash)
    || typeof value.resultHash !== "string"
    || !SHA256.test(value.resultHash)
    || typeof value.activeCapabilityHash !== "string"
    || !SHA256.test(value.activeCapabilityHash)
    || typeof value.dispatcherSha256 !== "string"
    || !SHA256.test(value.dispatcherSha256)
    || typeof value.timestamp !== "string"
    || !Number.isFinite(Date.parse(value.timestamp))
    || !plain(value.response)
  ) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated response payload is malformed.");
  }
  return value as unknown as AuthenticatedResponsePayload;
}

export function createAuthenticatedRequest(
  request: RemoteRequest,
  capability: VerifiedCapability,
  privateKey: Uint8Array,
  now = Date.now(),
  ttlSeconds = 30,
): { envelope: AuthenticatedRequestEnvelope; requestHash: string } {
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 5 || ttlSeconds > 60) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated request lifetime is invalid.");
  }
  const payload: AuthenticatedRequestPayload = {
    version: 2,
    request,
    capabilityHash: capability.hash,
    dispatcherSha256: capability.payload.dispatcherSha256,
    nonce: randomBytes(16).toString("hex"),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlSeconds * 1000).toISOString(),
  };
  const encoded = encode(payload);
  return {
    envelope: {
      version: 2,
      payload: encoded,
      signature: sign(null, Buffer.from(encoded, "utf8"), privateKey).toString("base64url"),
    },
    requestHash: sha256(payload),
  };
}

export async function verifyAuthenticatedRequest(
  value: unknown,
  capability: VerifiedCapability,
  publicKey: Uint8Array,
  replayDirectory: string,
  now = Date.now(),
): Promise<{ request: RemoteRequest; requestHash: string }> {
  const envelope = parseSignedEnvelope(value, "Authenticated request envelope");
  verifyEnvelopeSignature(envelope.payload, envelope.signature, publicKey, "Authenticated request");
  const payload = parseRequestPayload(decode(envelope.payload, "Authenticated request"));
  if (payload.capabilityHash !== capability.hash || payload.dispatcherSha256 !== capability.payload.dispatcherSha256) {
    throw new OpsHavenError("POLICY_DENIED", "Authenticated request does not bind the active capability and dispatcher.");
  }
  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  if (issuedAt > now + 30000 || expiresAt <= now || expiresAt <= issuedAt || expiresAt - issuedAt > 60000) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated request is stale or outside its allowed clock window.");
  }
  const requestHash = sha256(payload);
  await ensurePrivateDirectory(replayDirectory, "Request replay directory", "REMOTE_PROTOCOL_INVALID");
  try {
    await fs.writeFile(path.join(replayDirectory, payload.nonce), requestHash, { flag: "wx", mode: 0o600 });
  } catch (error: any) {
    if (error?.code === "EEXIST") throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated request nonce was replayed.");
    throw error;
  }
  return { request: payload.request, requestHash };
}

function responseResultHash(response: RemoteResponse): string {
  return sha256({ ok: response.ok, result: response.ok ? response.data : response.error, evidence: response.evidence });
}

export function createAuthenticatedResponse(
  response: RemoteResponse,
  requestHash: string,
  capability: VerifiedCapability,
  privateKey: Uint8Array,
  now = Date.now(),
): AuthenticatedResponseEnvelope {
  if (!SHA256.test(requestHash)) throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Originating request hash is invalid.");
  const payload: AuthenticatedResponsePayload = {
    version: 2,
    requestHash,
    resultHash: responseResultHash(response),
    activeCapabilityHash: capability.hash,
    dispatcherSha256: capability.payload.dispatcherSha256,
    timestamp: new Date(now).toISOString(),
    response,
  };
  const encoded = encode(payload);
  return {
    version: 2,
    payload: encoded,
    signature: sign(null, Buffer.from(encoded, "utf8"), privateKey).toString("base64url"),
  };
}

export function verifyAuthenticatedResponse(
  value: unknown,
  expectedRequestHash: string,
  expectedRequestId: string,
  capability: VerifiedCapability,
  publicKey: Uint8Array,
  now = Date.now(),
): RemoteResponse {
  const envelope = parseSignedEnvelope(value, "Authenticated response envelope");
  verifyEnvelopeSignature(envelope.payload, envelope.signature, publicKey, "Authenticated response");
  const payload = parseResponsePayload(decode(envelope.payload, "Authenticated response"));
  if (
    payload.requestHash !== expectedRequestHash
    || payload.activeCapabilityHash !== capability.hash
    || payload.dispatcherSha256 !== capability.payload.dispatcherSha256
  ) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated response does not match the originating request or active trust state.");
  }
  if (Math.abs(Date.parse(payload.timestamp) - now) > 120000) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated response timestamp is outside the allowed clock window.");
  }
  const response = parseRemoteResponse(payload.response, expectedRequestId);
  if (payload.resultHash !== responseResultHash(response)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_INVALID", "Authenticated response result hash is invalid.");
  }
  return response;
}

export function responsePrivateKeyPath(configPath: string): string {
  return `${configPath}.response-private.pem`;
}

export function responsePublicKeyPath(configPath: string): string {
  return `${configPath}.response-public.pem`;
}

export function requestReplayDirectory(config: OpsHavenConfig): string {
  return path.join(config.approvals.remoteUsedDirectory, "requests");
}

export async function loadClientProtocolContext(
  config: OpsHavenConfig,
  configPath: string,
  mode: CapabilityMode = "controlled",
): Promise<ClientProtocolContext> {
  const manifestText = await readRegularTextFile(capabilityManifestPath(configPath), "Capability manifest", {
    maxBytes: 1048576,
    code: "POLICY_DENIED",
  });
  let manifestValue: unknown;
  try {
    manifestValue = JSON.parse(manifestText) as unknown;
  } catch {
    throw new OpsHavenError("POLICY_DENIED", "Capability manifest is not valid JSON.");
  }
  const manifest = parseSignedCapabilityManifest(manifestValue);
  const decodedCapability = parseCapabilityPayload(decode(manifest.payload, "Capability"));
  const operatorPublicKey = await readRegularFile(config.approvals.verificationPublicKeyFile, "Operator public key", {
    maxBytes: 65536,
    code: "POLICY_DENIED",
  });
  const capability = verifyCapabilityManifest(config, manifest, operatorPublicKey, mode, decodedCapability.dispatcherSha256);
  return {
    capability,
    requestPrivateKey: await readRegularFile(config.approvals.signingPrivateKeyFile, "Request signing key", {
      ownerOnly: true,
      maxBytes: 65536,
      code: "POLICY_DENIED",
    }),
    responsePublicKey: await readRegularFile(responsePublicKeyPath(configPath), "Response verification key", {
      maxBytes: 65536,
      code: "POLICY_DENIED",
    }),
  };
}
