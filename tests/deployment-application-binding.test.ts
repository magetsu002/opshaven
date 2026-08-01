import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "../src/config.js";
import {
  applicationBinding,
  applicationFromConfig,
  generatedResources,
  type ApplicationRegistrationInput,
} from "../src/deployment/model.js";

const host = {
  id: "host.primary",
  kind: "host",
  address: "example.invalid",
  port: 22,
  user: "opshaven",
  knownHostsFile: "/tmp/opshaven-known-hosts",
  identityFile: "/tmp/opshaven-identity",
  connectTimeoutMs: 5000,
} as const;

function application(id: string, port: number): ApplicationRegistrationInput {
  return {
    id,
    name: id === "sample-api" ? "Sample API" : "Sample Worker",
    remoteTarget: host.id,
    repositoryLocation: `/srv/opshaven-fixtures/${id}/repository`,
    releaseLocation: `/srv/opshaven-fixtures/${id}/releases`,
    serviceIdentifier: `${id}.service`,
    healthCheckUrl: `http://127.0.0.1:${port}/health`,
    expectedStatus: 200,
  };
}

function config(policyVersion: string, resources: readonly Record<string, unknown>[]) {
  return parseConfig({
    version: 1,
    policyVersion,
    limits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    audit: { path: "/tmp/opshaven-audit.jsonl" },
    approvals: {
      directory: "/tmp/opshaven-approvals",
      secretFile: "/tmp/opshaven-approval-secret",
      signingPrivateKeyFile: "/tmp/opshaven-signing-private.pem",
      verificationPublicKeyFile: "/tmp/opshaven-verification-public.pem",
      remoteUsedDirectory: "/tmp/opshaven-remote-used",
      defaultTtlSeconds: 300,
    },
    secretFingerprints: [],
    resources,
  });
}

test("unrelated application registration does not invalidate an existing exact resource binding", () => {
  const apiInput = application("sample-api", 3000);
  const workerInput = application("sample-worker", 3001);
  const apiResources = generatedResources(apiInput, host.id);
  const initial = config("deployment-v3-apps-initial", [host, ...apiResources]);
  const registered = applicationFromConfig(initial, apiInput, initial.resources.get(host.id) as never, "2026-08-01T00:00:00.000Z");

  const expanded = config("deployment-v3-apps-expanded", [host, ...apiResources, ...generatedResources(workerInput, host.id)]);
  assert.doesNotThrow(() => applicationBinding(expanded, registered));
});

test("exact application resource substitution remains rejected", () => {
  const apiInput = application("sample-api", 3000);
  const apiResources = generatedResources(apiInput, host.id);
  const initial = config("deployment-v3-apps-initial", [host, ...apiResources]);
  const registered = applicationFromConfig(initial, apiInput, initial.resources.get(host.id) as never, "2026-08-01T00:00:00.000Z");
  const changed = apiResources.map((resource) => resource.id === "service.sample-api" ? { ...resource, unit: "other.service" } : resource);
  const tampered = config("deployment-v3-apps-initial", [host, ...changed]);
  assert.throws(() => applicationBinding(tampered, registered), /Application configuration changed after registration/);
});
