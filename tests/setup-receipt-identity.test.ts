import assert from "node:assert/strict";
import test from "node:test";
import {
  createCanonicalGenerationReceipt,
  verifyCanonicalGenerationReceipt,
  type CanonicalGenerationReceipt,
  type CanonicalGenerationReceiptInput,
} from "../src/setup/transaction.js";

function input(overrides: Partial<CanonicalGenerationReceiptInput> = {}): CanonicalGenerationReceiptInput {
  return {
    installationGeneration: 7,
    runtimeArtifactDigest: "1".repeat(64),
    dispatcherArtifactDigest: "2".repeat(64),
    policyDigest: "3".repeat(64),
    authorizationDigest: "4".repeat(64),
    applicationDeclarationDigest: "5".repeat(64),
    platform: "Linux",
    architecture: "x86_64",
    sourceBuildIdentity: "6".repeat(40),
    createdAt: "2026-08-01T16:30:00.000Z",
    previousGenerationIdentity: "7".repeat(64),
    ...overrides,
  };
}

function tamper(receipt: CanonicalGenerationReceipt, overrides: Partial<CanonicalGenerationReceipt>): CanonicalGenerationReceipt {
  return Object.freeze({ ...receipt, ...overrides });
}

test("canonical receipt identity is independent of upload and extraction paths", () => {
  const firstStagingPath = "/tmp/opshaven-stage-first";
  const secondStagingPath = "/tmp/opshaven-stage-second";
  const restorePath = "/var/lib/opshaven/transactions/example/previous";
  assert.notEqual(firstStagingPath, secondStagingPath);
  assert.notEqual(secondStagingPath, restorePath);
  const first = createCanonicalGenerationReceipt(input());
  const second = createCanonicalGenerationReceipt(input());
  assert.equal(first.identitySha256, second.identitySha256);
  assert.equal(verifyCanonicalGenerationReceipt(first), first);
});

test("modified artifact or receipt metadata fails integrity verification", () => {
  const receipt = createCanonicalGenerationReceipt(input());
  assert.throws(() => verifyCanonicalGenerationReceipt(tamper(receipt, { runtimeArtifactDigest: "8".repeat(64) })), /integrity/);
  assert.throws(() => verifyCanonicalGenerationReceipt(tamper(receipt, { createdAt: "2026-08-01T16:31:00.000Z" })), /integrity/);
});

test("wrong generation, dispatcher, policy, or previous binding is rejected", () => {
  const receipt = createCanonicalGenerationReceipt(input());
  assert.throws(() => verifyCanonicalGenerationReceipt(tamper(receipt, { installationGeneration: 8 })), /integrity/);
  assert.throws(() => verifyCanonicalGenerationReceipt(tamper(receipt, { dispatcherArtifactDigest: "9".repeat(64) })), /integrity/);
  assert.throws(() => verifyCanonicalGenerationReceipt(tamper(receipt, { policyDigest: "a".repeat(64) })), /integrity/);
  assert.throws(() => verifyCanonicalGenerationReceipt(tamper(receipt, { previousGenerationIdentity: "b".repeat(64) })), /integrity/);
});

test("canonical source validation remains strict", () => {
  assert.throws(() => createCanonicalGenerationReceipt(input({ sourceBuildIdentity: "main" })), /source build identity/);
  assert.throws(() => createCanonicalGenerationReceipt(input({ previousGenerationIdentity: "short" })), /previous-generation binding/);
  assert.throws(() => createCanonicalGenerationReceipt(input({ runtimeArtifactDigest: "not-a-digest" })), /runtimeArtifactDigest/);
});
