import assert from "node:assert/strict";
import test from "node:test";
import { promises as fs } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import type { HostResource } from "../src/config.js";
import { OpsHavenError } from "../src/errors.js";
import type { RemoteRequest } from "../src/remote/protocol.js";
import { FixedCommandRunner, type RunnerSpawnLike } from "../src/remote/runner.js";
import { SshTransport, type SpawnLike } from "../src/transport/ssh.js";

interface FakeStreams {
  stdin: { end(data: string): void };
  stdout: { on(event: string, listener: (chunk: Uint8Array) => void): void };
  stderr: { on(event: string, listener: (chunk: Uint8Array) => void): void };
  on(event: string, listener: (...args: any[]) => void): void;
  kill(signal?: string): void;
}

function emittingProcess(stdoutText: string, stderrText: string, exitCode: number): FakeStreams {
  let stdoutData: ((chunk: Uint8Array) => void) | undefined;
  let stderrData: ((chunk: Uint8Array) => void) | undefined;
  let close: ((code: number) => void) | undefined;
  return {
    stdin: { end() { if (stdoutText) stdoutData?.(Buffer.from(stdoutText)); if (stderrText) stderrData?.(Buffer.from(stderrText)); close?.(exitCode); } },
    stdout: { on(_event, listener) { stdoutData = listener; } },
    stderr: { on(_event, listener) { stderrData = listener; } },
    on(event, listener) { if (event === "close") close = listener as (code: number) => void; },
    kill() {},
  };
}

async function sshFixture(): Promise<{ host: HostResource; request: RemoteRequest }> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-output-bounds-"));
  const identityFile = path.join(root, "identity");
  const knownHostsFile = path.join(root, "known_hosts");
  await fs.writeFile(identityFile, "private", { mode: 0o600 });
  await fs.writeFile(knownHostsFile, "host key", { mode: 0o644 });
  return {
    host: { id: "host.main", kind: "host", address: "host.internal", port: 22, user: "opshaven", identityFile, knownHostsFile, connectTimeoutMs: 1000 },
    request: { version: 1, requestId: "output-bounds", operation: "get_host_summary", resourceId: "host.main", args: { resourceId: "host.main" }, limits: { timeoutMs: 1000, maxBytes: 1024, maxLines: 50 } },
  };
}

test("fixed command runner bounds stderr as part of total output", async () => {
  const spawnProcess = (() => emittingProcess("", "x".repeat(2048), 1)) as unknown as RunnerSpawnLike;
  await assert.rejects(new FixedCommandRunner(spawnProcess).run("/usr/bin/fixed-fixture", [], { timeoutMs: 1000, maxBytes: 1024, maxLines: 50 }), (error: unknown) => error instanceof OpsHavenError && error.code === "OUTPUT_LIMIT");
});

test("SSH transport bounds stderr and classifies pinned-host failures", async () => {
  const { host, request } = await sshFixture();
  const excessive = (() => emittingProcess("", "x".repeat(2048), 255)) as unknown as SpawnLike;
  await assert.rejects(new SshTransport(excessive).execute(host, request), (error: unknown) => error instanceof OpsHavenError && error.code === "OUTPUT_LIMIT");
  const changedKey = (() => emittingProcess("", "Host key verification failed.\n", 255)) as unknown as SpawnLike;
  await assert.rejects(new SshTransport(changedKey).execute(host, request), (error: unknown) => error instanceof OpsHavenError && error.code === "SSH_HOST_KEY_FAILED");
});
