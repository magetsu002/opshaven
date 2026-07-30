import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { parseConfig, type OpsHavenConfig } from "../src/config/schema.js";
import { createDeploymentHandlers } from "../src/dispatcher/deployment-handlers.js";
import { Dispatcher } from "../src/dispatcher/dispatcher.js";
import type { ProcessRequest, ProcessResult } from "../src/transport/process.js";

const CURRENT = "1111111111111111111111111111111111111111";
const NEXT = "2222222222222222222222222222222222222222";
const roots: string[] = [];

function output(stdout = "", exitCode = 0): ProcessResult {
  return { exitCode, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) };
}

async function fixture(): Promise<Readonly<{ config: OpsHavenConfig; root: string; active: string; state: string }>> {
  const root = await fs.mkdtemp("/tmp/opshaven-deploy-");
  roots.push(root);
  const repository = join(root, "repository");
  const releases = join(root, "releases");
  const stateDirectory = join(root, "state");
  const active = join(root, "current");
  const state = join(stateDirectory, "releases.json");
  await fs.mkdir(repository);
  await fs.mkdir(releases);
  await fs.mkdir(stateDirectory);
  await fs.mkdir(join(releases, CURRENT));
  await fs.symlink(join(releases, CURRENT), active);
  const raw = JSON.parse(await fs.readFile("examples/opshaven.config.json", "utf8")) as {
    deployments: Array<Record<string, unknown>>;
  };
  Object.assign(raw.deployments[0]!, {
    repositoryPath: repository,
    releasesPath: releases,
    activeSymlink: active,
    stateFile: state
  });
  return { config: parseConfig(raw), root, active, state };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => await fs.rm(root, { recursive: true, force: true })));
});

function request(dryRun: boolean) {
  return {
    version: 1 as const,
    requestId: "00000000-0000-4000-8000-000000000000",
    operation: "deploy_commit" as const,
    target: "demo-deployment",
    args: { deploymentId: "demo-deployment", commit: NEXT, acknowledgeMigrationRisk: true },
    expectedState: { currentCommit: CURRENT },
    dryRun,
    limits: { timeoutMs: 10_000, maxBytes: 65_536, maxLines: 500 }
  };
}

function successfulRunner(calls: ProcessRequest[]): (call: ProcessRequest) => Promise<ProcessResult> {
  return async (call) => {
    calls.push(call);
    if (call.args.includes("worktree") && call.args.includes("add")) {
      await fs.mkdir(call.args.at(-2)!);
      return output();
    }
    if (call.args.includes("worktree") && call.args.includes("remove")) {
      await fs.rm(call.args.at(-1)!, { recursive: true, force: true });
      return output();
    }
    if (call.args.includes("status")) return output();
    if (call.args.includes("rev-parse")) return output(NEXT);
    if (call.args.includes("merge-base")) return output();
    if (call.executable === "/usr/bin/systemctl") return output("active");
    return output();
  };
}

describe("safe configured Git deployment", () => {
  it("dry-run verifies the exact commit and changes nothing", async () => {
    const { config, active, state } = await fixture();
    const calls: ProcessRequest[] = [];
    const handlers = createDeploymentHandlers({
      runner: successfulRunner(calls),
      fs,
      fetcher: async () => new Response(null, { status: 200 }),
      now: () => new Date("2026-01-01T00:00:00.000Z")
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle(request(true));
    assert.equal(response.ok, true);
    assert.equal(await fs.readlink(active), join(config.deployments[0]!.releasesPath, CURRENT));
    await assert.rejects(fs.lstat(state), { code: "ENOENT" });
    assert.equal(calls.some((call) => call.args.includes("fetch")), false);
    assert.equal(calls.some((call) => call.args.includes("worktree")), false);
  });

  it("activates an exact allowed commit and records sanitized release state", async () => {
    const { config, active, state } = await fixture();
    const calls: ProcessRequest[] = [];
    const handlers = createDeploymentHandlers({
      runner: successfulRunner(calls),
      fs,
      fetcher: async () => new Response("secret body must not be read", { status: 200 }),
      now: () => new Date("2026-01-01T00:00:00.000Z")
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle(request(false));
    assert.equal(response.ok, true);
    assert.equal(await fs.readlink(active), join(config.deployments[0]!.releasesPath, NEXT));
    const recorded = JSON.parse(await fs.readFile(state, "utf8")) as { currentCommit: string };
    assert.equal(recorded.currentCommit, NEXT);
    assert.ok(calls.some((call) => call.executable === "/usr/bin/npm" && call.cwd?.endsWith(NEXT)));
    assert.ok(!JSON.stringify(response).includes("secret body"));
  });

  it("restores the prior release when health verification fails", async () => {
    const { config, active } = await fixture();
    const calls: ProcessRequest[] = [];
    const handlers = createDeploymentHandlers({
      runner: successfulRunner(calls),
      fs,
      fetcher: async () => new Response(null, { status: 503 }),
      now: () => new Date("2026-01-01T00:00:00.000Z")
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle(request(false));
    assert.equal(response.ok, false);
    assert.equal(await fs.readlink(active), join(config.deployments[0]!.releasesPath, CURRENT));
    assert.ok(JSON.stringify(response).includes("restoredPriorRelease"));
  });

  it("rejects dirty repositories before fetching or staging", async () => {
    const { config } = await fixture();
    const calls: ProcessRequest[] = [];
    const handlers = createDeploymentHandlers({
      runner: async (call) => {
        calls.push(call);
        return output(" M changed.txt");
      },
      fs,
      fetcher: async () => new Response(null, { status: 200 }),
      now: () => new Date()
    });
    const response = await new Dispatcher(config, handlers, "demo-host").handle(request(false));
    assert.equal(response.ok, false);
    assert.equal(calls.length, 1);
  });
});
