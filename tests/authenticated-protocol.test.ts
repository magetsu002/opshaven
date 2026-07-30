import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { canonicalize } from "../src/canonical.js";
import { OpsHavenError } from "../src/errors.js";
import {
  createAuthenticatedRequest,
  createAuthenticatedResponse,
  verifyAuthenticatedRequest,
  verifyAuthenticatedResponse,
  type AuthenticatedResponsePayload,
} from "../src/remote/authenticated-protocol.js";
import type { RemoteRequest, RemoteResponse } from "../src/remote/protocol.js";
import type { VerifiedCapability } from "../src/capabilities.js";

const requestKeys = generateKeyPairSync("ed25519");
const responseKeys = generateKeyPairSync("ed25519");
const requestPrivate = requestKeys.privateKey.export({ type: "pkcs8", format: "pem" }) as Uint8Array;
const requestPublic = requestKeys.publicKey.export({ type: "spki", format: "pem" }) as Uint8Array;
const responsePrivate = responseKeys.privateKey.export({ type: "pkcs8", format: "pem" }) as Uint8Array;
const responsePublic = responseKeys.publicKey.export({ type: "spki", format: "pem" }) as Uint8Array;
const now = Date.parse("2026-07-30T20:00:00.000Z");

const capability: VerifiedCapability = {
  hash: "c".repeat(64),
  payload: {
    version: 1,
    mode: "controlled",
    policyVersion: "v1",
    allowedOperations: ["get_service_status"],
    allowedResources: { get_service_status: ["svc.web"] },
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    dispatcherSha256: "d".repeat(64),
    issuedAt: "2026-07-30T19:00:00.000Z",
    expiresAt: "2026-07-30T21:00:00.000Z",
  },
};

const request: RemoteRequest = {
  version: 1,
  requestId: "request-auth-1",
  operation: "get_service_status",
  resourceId: "svc.web",
  args: { resourceId: "svc.web" },
  limits: { ...capability.payload.limits },
};

const response: RemoteResponse = {
  version: 1,
  requestId: request.requestId,
  ok: true,
  data: { activeState: "active" },
  evidence: { startedAt: "s", finishedAt: "f", truncated: false, redactions: 0 },
};

async function replayRoot(): Promise<string> {
  return await fs.mkdtemp(path.join(tmpdir(), "opshaven-request-replay-"));
}

function protocolFailure(error: unknown): boolean {
  return error instanceof OpsHavenError && error.code === "REMOTE_PROTOCOL_INVALID";
}

function mutateLastCharacter(value: string): string {
  return `${value.slice(0, -1)}${value.endsWith("A") ? "B" : "A"}`;
}

test("authenticated request binds arguments, capability, dispatcher, nonce, and time", async () => {
  const created = createAuthenticatedRequest(request, capability, requestPrivate, now, 30);
  const verified = await verifyAuthenticatedRequest(created.envelope, capability, requestPublic, await replayRoot(), now + 1000);
  assert.deepEqual(verified.request, request);
  assert.equal(verified.requestHash, created.requestHash);
});

test("authenticated request rejects replay, mutation, stale time, and trust mismatch", async () => {
  const directory = await replayRoot();
  const created = createAuthenticatedRequest(request, capability, requestPrivate, now, 30);
  await verifyAuthenticatedRequest(created.envelope, capability, requestPublic, directory, now + 1000);
  await assert.rejects(verifyAuthenticatedRequest(created.envelope, capability, requestPublic, directory, now + 1000), protocolFailure);
  const altered = { ...created.envelope, payload: mutateLastCharacter(created.envelope.payload) };
  await assert.rejects(verifyAuthenticatedRequest(altered, capability, requestPublic, await replayRoot(), now + 1000), protocolFailure);
  const stale = createAuthenticatedRequest(request, capability, requestPrivate, now - 120000, 30);
  await assert.rejects(verifyAuthenticatedRequest(stale.envelope, capability, requestPublic, await replayRoot(), now), protocolFailure);
  const otherCapability = { ...capability, hash: "e".repeat(64) };
  await assert.rejects(verifyAuthenticatedRequest(created.envelope, otherCapability, requestPublic, await replayRoot(), now + 1000));
});

test("authenticated response binds the originating request and result", () => {
  const created = createAuthenticatedRequest(request, capability, requestPrivate, now, 30);
  const envelope = createAuthenticatedResponse(response, created.requestHash, capability, responsePrivate, now + 1000);
  const verified = verifyAuthenticatedResponse(envelope, created.requestHash, request.requestId, capability, responsePublic, now + 2000);
  assert.equal(verified.ok, true);
  if (verified.ok) assert.equal(verified.data.activeState, "active");
});

test("authenticated response rejects signature, request, and result mutation", () => {
  const created = createAuthenticatedRequest(request, capability, requestPrivate, now, 30);
  const envelope = createAuthenticatedResponse(response, created.requestHash, capability, responsePrivate, now + 1000);
  assert.throws(() => verifyAuthenticatedResponse({ ...envelope, signature: mutateLastCharacter(envelope.signature) }, created.requestHash, request.requestId, capability, responsePublic, now + 2000), protocolFailure);
  assert.throws(() => verifyAuthenticatedResponse(envelope, "f".repeat(64), request.requestId, capability, responsePublic, now + 2000), protocolFailure);
  const decoded = JSON.parse(Buffer.from(envelope.payload, "base64url").toString("utf8")) as AuthenticatedResponsePayload;
  const tamperedPayload: AuthenticatedResponsePayload = {
    ...decoded,
    response: { ...response, data: { activeState: "tampered" } },
  };
  const encoded = Buffer.from(canonicalize(tamperedPayload), "utf8").toString("base64url");
  const resigned = {
    version: 2 as const,
    payload: encoded,
    signature: sign(null, Buffer.from(encoded, "utf8"), responsePrivate).toString("base64url"),
  };
  assert.throws(() => verifyAuthenticatedResponse(resigned, created.requestHash, request.requestId, capability, responsePublic, now + 2000), protocolFailure);
});
