import { dirname, join } from "node:path";
import type { CommandStep, DeploymentConfig, OpsHavenConfig, ProbeConfig } from "../config/schema.js";
import { OpsHavenError, errorMessage } from "../core/errors.js";
import type { JsonValue } from "../security/canonical.js";
import type { DispatcherHandlers } from "./dispatcher.js";
import {
  activateRelease,
  assertPathAbsent,
  assertSafeDirectory,
  NODE_DEPLOYMENT_FILE_SYSTEM,
  readActiveRelease,
  readDeploymentState,
  writeDeploymentState,
  type DeploymentFileSystem,
  type DeploymentState,
  type ReleaseRecord
} from "./deployment-state.js";
import {
  assertArgs,
  assertTarget,
  DEFAULT_RUNTIME,
  findResource,
  fixedCommand,
  type HandlerRuntime
} from "./runtime.js";

export type DeploymentFetch = (
  input: string,
  init: Readonly<{ method: "GET"; redirect: "manual"; signal: AbortSignal; headers: Readonly<Record<string, string>> }>
) => Promise<Response>;

export type DeploymentRuntime = HandlerRuntime & Readonly<{
  fs: DeploymentFileSystem;
  fetcher: DeploymentFetch;
  now: () => Date;
}>;

const DEFAULT_DEPLOYMENT_RUNTIME: DeploymentRuntime = Object.freeze({
  ...DEFAULT_RUNTIME,
  fs: NODE_DEPLOYMENT_FILE_SYSTEM,
  fetcher: async (input, init) => await fetch(input, init),
  now: () => new Date()
});

const EXECUTABLES: Readonly<Record<CommandStep["executable"], string>> = Object.freeze({
  npm: "/usr/bin/npm",
  pnpm: "/usr/bin/pnpm",
  yarn: "/usr/bin/yarn",
  node: "/usr/bin/node",
  docker: "/usr/bin/docker"
});

function exactExpectedCommit(request: Parameters<NonNullable<DispatcherHandlers["deploy_commit"]>>[0]): string {
  const fields = Object.keys(request.expectedState);
  if (fields.length !== 1 || fields[0] !== "currentCommit") {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Deployment expected state must contain only currentCommit");
  }
  const currentCommit = request.expectedState.currentCommit;
  if (typeof currentCommit !== "string" || !/^[a-f0-9]{40}$/.test(currentCommit)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Deployment expected current commit is invalid");
  }
  return currentCommit;
}

function rollbackArgs(request: Parameters<NonNullable<DispatcherHandlers["rollback_deployment"]>>[0]): Readonly<{
  deploymentId: string;
  releaseCommit: string;
}> {
  assertArgs(request, ["deploymentId", "releaseCommit"]);
  const { deploymentId, releaseCommit } = request.args;
  if (typeof deploymentId !== "string" || typeof releaseCommit !== "string" || !/^[a-f0-9]{40}$/.test(releaseCommit)) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Rollback arguments are malformed");
  }
  return { deploymentId, releaseCommit };
}

function deploymentArgs(request: Parameters<NonNullable<DispatcherHandlers["deploy_commit"]>>[0]): Readonly<{
  deploymentId: string;
  commit: string;
  acknowledgeMigrationRisk: boolean;
}> {
  assertArgs(request, ["deploymentId", "commit", "acknowledgeMigrationRisk"]);
  const { deploymentId, commit, acknowledgeMigrationRisk } = request.args;
  if (
    typeof deploymentId !== "string" ||
    typeof commit !== "string" ||
    !/^[a-f0-9]{40}$/.test(commit) ||
    typeof acknowledgeMigrationRisk !== "boolean"
  ) {
    throw new OpsHavenError("REMOTE_PROTOCOL_ERROR", "Deployment arguments are malformed");
  }
  return { deploymentId, commit, acknowledgeMigrationRisk };
}

async function verifySafeLayout(runtime: DeploymentRuntime, deployment: DeploymentConfig): Promise<void> {
  await assertSafeDirectory(runtime.fs, deployment.repositoryPath, "Deployment repository");
  await assertSafeDirectory(runtime.fs, deployment.releasesPath, "Deployment releases directory");
  await assertSafeDirectory(runtime.fs, dirname(deployment.activeSymlink), "Deployment activation directory");
  await assertSafeDirectory(runtime.fs, dirname(deployment.stateFile), "Deployment state directory");
}

async function verifyRepositoryClean(
  runtime: DeploymentRuntime,
  request: Parameters<NonNullable<DispatcherHandlers["deploy_commit"]>>[0],
  deployment: DeploymentConfig
): Promise<void> {
  const status = await fixedCommand(
    runtime,
    request,
    "/usr/bin/git",
    ["-C", deployment.repositoryPath, "status", "--porcelain=v1", "--untracked-files=normal"]
  );
  if (status.stdout !== "") {
    throw new OpsHavenError("POLICY_DENIED", "Deployment repository has dirty or conflicting state");
  }
}

async function verifyCommitAllowed(
  runtime: DeploymentRuntime,
  request: Parameters<NonNullable<DispatcherHandlers["deploy_commit"]>>[0],
  deployment: DeploymentConfig,
  commit: string
): Promise<void> {
  const verified = await fixedCommand(
    runtime,
    request,
    "/usr/bin/git",
    ["-C", deployment.repositoryPath, "rev-parse", "--verify", `${commit}^{commit}`]
  );
  if (verified.stdout !== commit) {
    throw new OpsHavenError("POLICY_DENIED", "Requested deployment object is not the exact configured commit");
  }
  let allowed = false;
  for (const ref of deployment.allowedRefs) {
    const reachable = await fixedCommand(
      runtime,
      request,
      "/usr/bin/git",
      ["-C", deployment.repositoryPath, "merge-base", "--is-ancestor", commit, ref],
      { allowExitCodes: [0, 1] }
    );
    if (reachable.exitCode === 0) allowed = true;
  }
  if (!allowed) {
    throw new OpsHavenError("POLICY_DENIED", "Requested commit is not reachable from an allowed ref");
  }
}

async function runConfiguredSteps(
  runtime: DeploymentRuntime,
  request: Parameters<NonNullable<DispatcherHandlers["deploy_commit"]>>[0],
  releasePath: string,
  steps: readonly CommandStep[],
  phase: "check" | "build"
): Promise<readonly JsonValue[]> {
  const evidence: JsonValue[] = [];
  for (const [index, step] of steps.entries()) {
    const result = await fixedCommand(runtime, request, EXECUTABLES[step.executable], step.args, {
      timeoutMs: step.timeoutMs,
      cwd: releasePath
    });
    evidence.push({ phase, index, executable: step.executable, exitCode: result.exitCode });
  }
  return evidence;
}

async function activateConfiguredResources(
  runtime: DeploymentRuntime,
  request: Parameters<NonNullable<DispatcherHandlers["deploy_commit"]>>[0],
  config: OpsHavenConfig,
  deployment: DeploymentConfig
): Promise<readonly JsonValue[]> {
  const evidence: JsonValue[] = [];
  if (deployment.strategy === "docker-compose") {
    await fixedCommand(runtime, request, "/usr/bin/sudo", [
      "-n",
      "/usr/bin/docker",
      "compose",
      "--project-directory",
      deployment.activeSymlink,
      "up",
      "-d",
      "--remove-orphans"
    ]);
    evidence.push({ strategy: "docker-compose", activated: true });
    return evidence;
  }
  for (const serviceId of deployment.serviceIds) {
    const service = findResource(config.services, serviceId, deployment.hostId, "service");
    await fixedCommand(runtime, request, "/usr/bin/sudo", ["-n", "/usr/bin/systemctl", "restart", service.unit]);
    const active = await fixedCommand(runtime, request, "/usr/bin/systemctl", ["is-active", service.unit], {
      allowExitCodes: [0, 3, 4]
    });
    if (active.exitCode !== 0 || active.stdout !== "active") {
      throw new OpsHavenError("OPERATION_FAILED", "Configured service did not become active after deployment", {
        serviceId,
        observed: active.stdout || "unknown"
      });
    }
    evidence.push({ serviceId, unit: service.unit, activeState: "active" });
  }
  return evidence;
}

async function verifyProbe(runtime: DeploymentRuntime, probe: ProbeConfig, timeoutMs: number): Promise<JsonValue> {
  const response = await runtime.fetcher(probe.url, {
    method: "GET",
    redirect: "manual",
    signal: AbortSignal.timeout(Math.min(probe.timeoutMs, timeoutMs)),
    headers: { Accept: "application/json,text/plain;q=0.5" }
  });
  await response.body?.cancel();
  if (!probe.expectedStatus.includes(response.status)) {
    throw new OpsHavenError("OPERATION_FAILED", "Deployment health verification failed", {
      probeId: probe.id,
      status: response.status
    });
  }
  return { probeId: probe.id, status: response.status, bodyExposed: false };
}

async function verifyHealth(
  runtime: DeploymentRuntime,
  request: Parameters<NonNullable<DispatcherHandlers["deploy_commit"]>>[0],
  config: OpsHavenConfig,
  deployment: DeploymentConfig
): Promise<readonly JsonValue[]> {
  const evidence: JsonValue[] = [];
  for (const probeId of deployment.probeIds) {
    const probe = findResource(config.probes, probeId, deployment.hostId, "probe");
    evidence.push(await verifyProbe(runtime, probe, request.limits.timeoutMs));
  }
  return evidence;
}

function updateState(
  prior: DeploymentState,
  deployment: DeploymentConfig,
  currentCommit: string,
  commit: string,
  activatedAt: string
): DeploymentState {
  const priorRecord: ReleaseRecord = prior.releases.find((item) => item.commit === currentCommit) ?? {
    commit: currentCommit,
    path: join(deployment.releasesPath, currentCommit),
    activatedAt,
    previousCommit: currentCommit,
    migrationRisk: "none"
  };
  const nextRecord: ReleaseRecord = {
    commit,
    path: join(deployment.releasesPath, commit),
    activatedAt,
    previousCommit: currentCommit,
    migrationRisk: deployment.migrationRisk
  };
  return {
    version: 1,
    currentCommit: commit,
    releases: [...prior.releases.filter((item) => item.commit !== currentCommit && item.commit !== commit), priorRecord, nextRecord]
  };
}

async function removeFailedWorktree(
  runtime: DeploymentRuntime,
  request: Parameters<NonNullable<DispatcherHandlers["deploy_commit"]>>[0],
  deployment: DeploymentConfig,
  releasePath: string
): Promise<void> {
  await fixedCommand(
    runtime,
    request,
    "/usr/bin/git",
    ["-C", deployment.repositoryPath, "worktree", "remove", "--force", releasePath],
    { allowExitCodes: [0, 128] }
  ).catch(() => undefined);
}

export function createDeploymentHandlers(runtime: DeploymentRuntime = DEFAULT_DEPLOYMENT_RUNTIME): DispatcherHandlers {
  return {
    deploy_commit: async (request, config, dispatcherHostId) => {
      const args = deploymentArgs(request);
      const deployment = findResource(config.deployments, args.deploymentId, dispatcherHostId, "deployment");
      assertTarget(request, deployment.id);
      if (deployment.migrationRisk === "manual-review" && !args.acknowledgeMigrationRisk) {
        throw new OpsHavenError("POLICY_DENIED", "Deployment requires migration-risk acknowledgement");
      }
      const expectedCurrentCommit = exactExpectedCommit(request);
      await verifySafeLayout(runtime, deployment);
      const active = await readActiveRelease(runtime.fs, deployment.activeSymlink, deployment.releasesPath);
      if (active.commit !== expectedCurrentCommit) {
        throw new OpsHavenError("POLICY_DENIED", "Active release changed since approval was resolved", {
          expected: expectedCurrentCommit,
          observed: active.commit
        });
      }
      await verifyRepositoryClean(runtime, request, deployment);
      if (!request.dryRun) {
        await fixedCommand(runtime, request, "/usr/bin/git", ["-C", deployment.repositoryPath, "fetch", "--prune", "origin"]);
      }
      await verifyCommitAllowed(runtime, request, deployment, args.commit);
      const releasePath = join(deployment.releasesPath, args.commit);
      await assertPathAbsent(runtime.fs, releasePath, "Requested release directory");
      if (request.dryRun) {
        return {
          deploymentId: deployment.id,
          commit: args.commit,
          currentCommit: active.commit,
          dryRun: true,
          changed: false,
          plannedChecks: deployment.checkSteps.length,
          plannedBuildSteps: deployment.buildSteps.length,
          plannedServices: deployment.serviceIds,
          plannedProbes: deployment.probeIds,
          migrationRisk: deployment.migrationRisk
        };
      }

      let activated = false;
      try {
        await fixedCommand(runtime, request, "/usr/bin/git", [
          "-C",
          deployment.repositoryPath,
          "worktree",
          "add",
          "--detach",
          releasePath,
          args.commit
        ]);
        await assertSafeDirectory(runtime.fs, releasePath, "Prepared release");
        const checks = await runConfiguredSteps(runtime, request, releasePath, deployment.checkSteps, "check");
        const builds = await runConfiguredSteps(runtime, request, releasePath, deployment.buildSteps, "build");
        await activateRelease(runtime.fs, deployment.activeSymlink, releasePath, deployment.releasesPath);
        activated = true;
        const activation = await activateConfiguredResources(runtime, request, config, deployment);
        const probes = await verifyHealth(runtime, request, config, deployment);
        const activatedAt = runtime.now().toISOString();
        const state = updateState(
          await readDeploymentState(runtime.fs, deployment.stateFile),
          deployment,
          active.commit,
          args.commit,
          activatedAt
        );
        await writeDeploymentState(runtime.fs, deployment.stateFile, state);
        return {
          deploymentId: deployment.id,
          previousCommit: active.commit,
          commit: args.commit,
          activatedAt,
          changed: true,
          migrationRisk: deployment.migrationRisk,
          checks,
          builds,
          activation,
          probes
        };
      } catch (error) {
        let restoredPriorRelease = false;
        if (activated) {
          try {
            await activateRelease(runtime.fs, deployment.activeSymlink, active.target, deployment.releasesPath);
            await activateConfiguredResources(runtime, request, config, deployment);
            restoredPriorRelease = true;
          } catch (restoreError) {
            throw new OpsHavenError("OPERATION_FAILED", "Deployment failed and prior release restoration also failed", {
              deploymentFailure: errorMessage(error),
              restorationFailure: errorMessage(restoreError)
            });
          }
        }
        await removeFailedWorktree(runtime, request, deployment, releasePath);
        throw new OpsHavenError("OPERATION_FAILED", "Deployment transaction failed", {
          reason: errorMessage(error),
          restoredPriorRelease
        });
      }
    },

    rollback_deployment: async (request, config, dispatcherHostId) => {
      const args = rollbackArgs(request);
      const deployment = findResource(config.deployments, args.deploymentId, dispatcherHostId, "deployment");
      assertTarget(request, deployment.id);
      const expectedCurrentCommit = exactExpectedCommit(request);
      await verifySafeLayout(runtime, deployment);
      const active = await readActiveRelease(runtime.fs, deployment.activeSymlink, deployment.releasesPath);
      if (active.commit !== expectedCurrentCommit) {
        throw new OpsHavenError("POLICY_DENIED", "Active release changed since approval was resolved", {
          expected: expectedCurrentCommit,
          observed: active.commit
        });
      }
      if (args.releaseCommit === active.commit) {
        throw new OpsHavenError("POLICY_DENIED", "Rollback target is already active");
      }
      const state = await readDeploymentState(runtime.fs, deployment.stateFile);
      if (state.currentCommit !== active.commit) {
        throw new OpsHavenError("POLICY_DENIED", "Recorded deployment state does not match the active release");
      }
      const release = state.releases.find((item) => item.commit === args.releaseCommit);
      const expectedPath = join(deployment.releasesPath, args.releaseCommit);
      if (release === undefined || release.path !== expectedPath) {
        throw new OpsHavenError("POLICY_DENIED", "Rollback target is not a known recorded release");
      }
      await assertSafeDirectory(runtime.fs, expectedPath, "Recorded rollback release");
      if (request.dryRun) {
        return {
          deploymentId: deployment.id,
          currentCommit: active.commit,
          releaseCommit: release.commit,
          dryRun: true,
          changed: false,
          migrationRisk: release.migrationRisk,
          databaseMigrationReversalAttempted: false
        };
      }

      let activated = false;
      try {
        await activateRelease(runtime.fs, deployment.activeSymlink, expectedPath, deployment.releasesPath);
        activated = true;
        const activation = await activateConfiguredResources(runtime, request, config, deployment);
        const probes = await verifyHealth(runtime, request, config, deployment);
        await writeDeploymentState(runtime.fs, deployment.stateFile, {
          version: 1,
          currentCommit: release.commit,
          releases: state.releases
        });
        return {
          deploymentId: deployment.id,
          previousCommit: active.commit,
          commit: release.commit,
          changed: true,
          migrationRisk: release.migrationRisk,
          databaseMigrationReversalAttempted: false,
          activation,
          probes
        };
      } catch (error) {
        let restoredPriorRelease = false;
        if (activated) {
          try {
            await activateRelease(runtime.fs, deployment.activeSymlink, active.target, deployment.releasesPath);
            await activateConfiguredResources(runtime, request, config, deployment);
            restoredPriorRelease = true;
          } catch (restoreError) {
            throw new OpsHavenError("OPERATION_FAILED", "Rollback failed and active release restoration also failed", {
              rollbackFailure: errorMessage(error),
              restorationFailure: errorMessage(restoreError)
            });
          }
        }
        throw new OpsHavenError("OPERATION_FAILED", "Rollback transaction failed", {
          reason: errorMessage(error),
          restoredPriorRelease
        });
      }
    }
  };
}

