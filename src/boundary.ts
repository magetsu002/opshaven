import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { AuditLog } from "./audit.js";
import type { HostResource, OpsHavenConfig } from "./config.js";
import { OpsHavenError } from "./errors.js";
import {
  createAuthenticatedRequest,
  loadClientProtocolContext,
  verifyAuthenticatedResponse,
} from "./remote/authenticated-protocol.js";
import type { RemoteRequest } from "./remote/protocol.js";
import { ReadOnlyPolicyEngine } from "./remote/read-only-policy.js";
import { buildSshArgs } from "./transport/ssh.js";

export interface BoundaryAssertion {
  name: string;
  passed: boolean;
  detail: string;
}

export interface BoundaryReport {
  ok: boolean;
  checkedAt: string;
  assertions: BoundaryAssertion[];
}

async function runSsh(
  host: HostResource,
  stdin: string,
  command?: string,
  knownHostsFile = host.knownHostsFile,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const args = buildSshArgs({ ...host, knownHostsFile });
  if (command) args.push(command);
  return await new Promise((resolve) => {
    const child = spawn("/usr/bin/ssh", args, {
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    });
    const stdout: Uint8Array[] = [];
    const stderr: Uint8Array[] = [];
    child.stdout.on("data", (chunk: Uint8Array) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Uint8Array) => stderr.push(chunk));
    child.on("close", (code: number | null) => resolve({
      code,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
    }));
    child.on("error", () => resolve({ code: 255, stdout: "", stderr: "SSH start failed" }));
    child.stdin.end(stdin);
  });
}

function deniedOriginal(result: { stdout: string; stderr: string }): boolean {
  const combined = `${result.stdout}\n${result.stderr}`;
  return combined.includes("POLICY_DENIED") && !/uid=|gid=|groups=|Docker version|permission granted/i.test(combined);
}

function resultAssertion(name: string, passed: boolean, detail: string): BoundaryAssertion {
  return { name, passed, detail };
}

function selectedHost(config: OpsHavenConfig): HostResource {
  const found = [...config.resources.values()].find((resource) => resource.kind === "host");
  if (!found || found.kind !== "host") throw new OpsHavenError("CONFIG_INVALID", "Boundary verification requires a configured host resource.");
  return found;
}

export async function verifyBoundary(config: OpsHavenConfig, configPath: string): Promise<BoundaryReport> {
  const host = selectedHost(config);
  const assertions: BoundaryAssertion[] = [];
  const trust = await loadClientProtocolContext(config, configPath, "controlled");

  for (const [name, command] of [
    ["interactive shell denied", "/bin/sh"],
    ["arbitrary SSH commands denied", "id"],
    ["sudo unavailable", "sudo -n true"],
    ["write access denied", "touch /tmp/opshaven-boundary-write"],
    ["Docker socket unavailable", "docker version"],
  ] as const) {
    const result = await runSsh(host, "", command);
    assertions.push(resultAssertion(name, deniedOriginal(result), "forced-command policy denial"));
  }

  const baseRequest: RemoteRequest = {
    version: 1,
    requestId: "boundary-valid",
    operation: "get_host_summary",
    resourceId: host.id,
    args: { resourceId: host.id },
    limits: { ...config.limits },
  };
  const valid = createAuthenticatedRequest(baseRequest, trust.capability, trust.requestPrivateKey);
  const validWire = await runSsh(host, `${JSON.stringify(valid.envelope)}\n`);
  let validResponse = false;
  let responseEnvelope: unknown;
  try {
    responseEnvelope = JSON.parse(validWire.stdout) as unknown;
    const response = verifyAuthenticatedResponse(responseEnvelope, valid.requestHash, baseRequest.requestId, trust.capability, trust.responsePublicKey);
    validResponse = response.ok;
  } catch {
    validResponse = false;
  }
  assertions.push(resultAssertion("artifact and capability hashes valid", validResponse, "authenticated remote inspection succeeded"));

  for (const [name, request] of [
    ["unknown operation denied", { ...baseRequest, requestId: "boundary-unknown-op", operation: "unknown_operation" }],
    ["unknown resource denied", { ...baseRequest, requestId: "boundary-unknown-resource", resourceId: "host.unknown", args: { resourceId: "host.unknown" } }],
  ] as const) {
    const created = createAuthenticatedRequest(request as RemoteRequest, trust.capability, trust.requestPrivateKey);
    const wire = await runSsh(host, `${JSON.stringify(created.envelope)}\n`);
    let passed = false;
    try {
      const response = verifyAuthenticatedResponse(JSON.parse(wire.stdout) as unknown, created.requestHash, request.requestId, trust.capability, trust.responsePublicKey);
      passed = !response.ok && /UNKNOWN_|POLICY_DENIED/.test(response.error.code);
    } catch {
      passed = false;
    }
    assertions.push(resultAssertion(name, passed, "signed remote denial"));
  }

  let readOnlyUnavailable = false;
  try {
    new ReadOnlyPolicyEngine(config).resolve("restart_service", { resourceId: host.id, dryRun: false });
  } catch (error) {
    readOnlyUnavailable = error instanceof OpsHavenError && error.code === "UNKNOWN_OPERATION";
  }
  assertions.push(resultAssertion("read-only mutations unavailable", readOnlyUnavailable, "operation absent from isolated policy table"));

  const replay = await runSsh(host, `${JSON.stringify(valid.envelope)}\n`);
  let replayDenied = false;
  try {
    const parsed = JSON.parse(replay.stdout) as Record<string, unknown>;
    replayDenied = parsed.ok === false && (parsed.error as Record<string, unknown> | undefined)?.code === "REMOTE_PROTOCOL_INVALID";
  } catch {
    replayDenied = false;
  }
  assertions.push(resultAssertion("request replay denied", replayDenied, "atomic nonce consumption"));

  const mutated = { ...valid.envelope, payload: `${valid.envelope.payload.slice(0, -1)}A` };
  const mutationWire = await runSsh(host, `${JSON.stringify(mutated)}\n`);
  let mutationDenied = false;
  try {
    const parsed = JSON.parse(mutationWire.stdout) as Record<string, unknown>;
    mutationDenied = parsed.ok === false && (parsed.error as Record<string, unknown> | undefined)?.code === "REMOTE_PROTOCOL_INVALID";
  } catch {
    mutationDenied = false;
  }
  assertions.push(resultAssertion("request mutation denied", mutationDenied, "Ed25519 request signature"));

  let responseMutationDenied = false;
  if (responseEnvelope && typeof responseEnvelope === "object") {
    try {
      const candidate = responseEnvelope as Record<string, unknown>;
      verifyAuthenticatedResponse(
        { ...candidate, payload: `${String(candidate.payload).slice(0, -1)}A` },
        valid.requestHash,
        baseRequest.requestId,
        trust.capability,
        trust.responsePublicKey,
      );
    } catch (error) {
      responseMutationDenied = error instanceof OpsHavenError;
    }
  }
  assertions.push(resultAssertion("response mutation denied", responseMutationDenied, "Ed25519 response signature and result hash"));

  const fakeKnownHosts = path.join(await fs.mkdtemp(path.join(tmpdir(), "opshaven-boundary-hostkey-")), "known_hosts");
  await fs.writeFile(fakeKnownHosts, "[127.0.0.1]:1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", { mode: 0o600 });
  const mismatch = await runSsh(host, "", undefined, fakeKnownHosts);
  assertions.push(resultAssertion("host-key mismatch denied", mismatch.code !== 0 && /Host key|known hosts|verification/i.test(mismatch.stderr), "strict pinned host-key verification"));

  const audit = await new AuditLog(config.audit.path).verify();
  assertions.push(resultAssertion("audit chain valid", audit.valid, `${audit.records} records verified`));

  return {
    ok: assertions.every((assertion) => assertion.passed),
    checkedAt: new Date().toISOString(),
    assertions,
  };
}

export function formatBoundaryReport(report: BoundaryReport): string {
  const lines = report.assertions.map((assertion) => `${assertion.passed ? "PASS" : "FAIL"}  ${assertion.name}: ${assertion.detail}`);
  lines.push(report.ok ? "Boundary verification passed." : "Boundary verification failed.");
  return `${lines.join("\n")}\n`;
}
