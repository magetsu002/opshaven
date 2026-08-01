import { createHash, randomBytes } from "node:crypto";
import { constants, promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { canonicalize, sha256 } from "../canonical.js";
import type { DeploymentResource, HostResource, OpsHavenConfig, ProbeResource, ServiceResource } from "../config.js";
import { OpsHavenError } from "../errors.js";
import type { ResultEnvelope } from "../operations.js";
import { ensurePrivateDirectory, readRegularFile, readRegularTextFile } from "../safe-fs.js";

const APP_ID = /^[a-z][a-z0-9-]{0,47}$/;
const APP_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,119}$/;
const RESOURCE_ID = /^[a-z][a-z0-9._-]{0,63}$/;
const PLAN_ID = /^sha256:([a-f0-9]{64})$/;
const COMMIT_SHA = /^[a-f0-9]{40}$/i;
const NONCE = /^[a-f0-9]{32}$/;
const SERVICE = /^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,119}\.service$/;
const SAFE_PATH = /^\/[A-Za-z0-9._/-]{1,4095}$/;
export const DEPLOYMENT_PLAN_TTL_MS = 15 * 60 * 1000;
export const DEPLOYMENT_MINIMUM_DISK_BYTES = 256 * 1024 * 1024;
export const DEPLOYMENT_BUILD_STRATEGY = "git-systemd-http-v1" as const;
export const DEPLOYMENT_ROLLBACK_BEHAVIOR = "automatic" as const;
export const DEPLOYMENT_OPERATION_VERSION = "deployment-operations-v1";
const NPM = "/usr/bin/npm";

export type DeploymentOutcome =
  | "DEPLOYMENT_SUCCEEDED"
  | "DEPLOYMENT_FAILED_ROLLED_BACK"
  | "DEPLOYMENT_FAILED_ROLLBACK_FAILED"
  | "DEPLOYMENT_NOT_STARTED";

export type DeploymentOperationKind =
  | "verify_revision"
  | "inspect_current_release"
  | "check_disk_space"
  | "prepare_release"
  | "fetch_verified_source"
  | "build_release"
  | "record_rollback_point"
  | "activate_release"
  | "restart_service"
  | "run_health_check"
  | "confirm_revision"
  | "restore_release";

export interface DeploymentApplication {
  schemaVersion: 1;
  id: string;
  name: string;
  targetLabel: string;
  hostResourceId: string;
  applicationResourceId: string;
  deploymentResourceId: string;
  serviceResourceId: string;
  probeResourceId: string;
  repositoryLocation: string;
  releaseLocation: string;
  currentReleaseLocation: string;
  serviceIdentifier: string;
  healthCheckUrl: string;
  expectedStatus: number;
  buildStrategy: typeof DEPLOYMENT_BUILD_STRATEGY;
  rollbackBehavior: typeof DEPLOYMENT_ROLLBACK_BEHAVIOR;
  resourceBindingDigest: string;
  createdAt: string;
}

export interface ApplicationRegistrationInput {
  id: string;
  name: string;
  remoteTarget: string;
  repositoryLocation: string;
  releaseLocation: string;
  serviceIdentifier: string;
  healthCheckUrl: string;
  expectedStatus?: number;
  buildStrategy?: string;
  rollbackBehavior?: string;
}

export interface DeploymentOperation {
  kind: DeploymentOperationKind;
  inputs: Readonly<Record<string, string | number | boolean>>;
  permittedResources: readonly string[];
  requiredPrivilege: "restricted-remote-user" | "approved-systemd-restart";
  timeoutMs: number;
  outputBound: { maxBytes: number; maxLines: number };
  redaction: "structured-only" | "bounded-redacted-output";
  mutation: "none" | "release-state" | "service-state";
  verification: string;
  rollback: string | null;
}

export interface ObservedDeploymentState {
  currentRevision: string;
  activeReleaseId: string;
  sourceRepositoryRevision: string;
  sourceRepositoryDirty: boolean;
  serviceIdentifier: string;
  serviceActiveState: string;
  serviceSubState: string;
  serviceExitStatus: number;
  healthReachable: boolean;
  healthExpected: boolean;
  healthStatusCode: number;
  availableDiskBytes: number;
  runtimeAvailable: boolean;
  rollbackAvailable: boolean;
  targetRevisionVerified: boolean;
}

export interface DeploymentPlan {
  schemaVersion: 1;
  applicationId: string;
  target: { label: string; hostResourceId: string; identityDigest: string };
  observedStateFingerprint: string;
  observed: ObservedDeploymentState;
  currentRevision: string;
  targetRevision: string;
  operations: readonly DeploymentOperation[];
  requiredAuthorization: {
    mechanism: "opshaven-exact-operation-approval-v1";
    operatorProfileDigest: string;
    scopeDigest: string;
  };
  requiredPrivileges: readonly string[];
  healthChecks: readonly {
    probeResourceId: string;
    endpointDigest: string;
    expectedStatus: number;
    timeoutMs: number;
    exactRevisionEvidence: boolean;
  }[];
  rollback: {
    strategy: "restore-previous-active-release";
    available: boolean;
    releaseId: string;
    revision: string;
    operations: readonly DeploymentOperation[];
  };
  risk: {
    classification: "controlled-application-release";
    mutatesReleaseState: true;
    restartsApprovedServices: readonly string[];
    migrations: "unsupported";
  };
  policyVersion: string;
  applicationConfigDigest: string;
  operationDefinitionsDigest: string;
  createdAt: string;
  expiresAt: string;
  nonce: string;
}

export interface StoredDeploymentPlan { planId: string; plan: DeploymentPlan }

export interface DeploymentApplyResult {
  planId: string;
  applicationId: string;
  targetRevision: string;
  currentRevision: string;
  outcome: DeploymentOutcome;
  failure: string | null;
  rollbackAttempted: boolean;
  activeRevision: string;
  healthVerified: boolean;
}

export interface OperationClient {
  execute(operationName: string, args: unknown, approvalToken?: string, actor?: string): Promise<ResultEnvelope>;
  createApproval(operationName: string, args: unknown, ttlSeconds?: number): Promise<{ token: string; digest: string; expiresAt: string; operationDigest: string }>;
}

export interface ProtectedDocument { text: string; mode: number; dev: number; ino: number }

export interface ExecutionStart {
  schemaVersion: 1;
  planId: string;
  applicationId: string;
  operatorProfileDigest: string;
  startedAt: string;
}

export interface ExecutionResultRecord {
  schemaVersion: 1;
  planId: string;
  applicationId: string;
  finishedAt: string;
  outcome: DeploymentOutcome;
  evidenceDigest: string;
}

export function validateApplicationId(value: string): string {
  if (!APP_ID.test(value)) throw new OpsHavenError("CONFIG_INVALID", "Application ID must start with a letter and contain only lowercase letters, numbers, and hyphens.");
  return value;
}

export function validateApplicationName(value: string): string {
  const selected = value.trim();
  if (!APP_NAME.test(selected)) throw new OpsHavenError("CONFIG_INVALID", "Application name contains unsupported characters.");
  return selected;
}

export function validateServiceIdentifier(value: string): string {
  if (!SERVICE.test(value)) throw new OpsHavenError("CONFIG_INVALID", "Service identifier must be one approved systemd .service unit.");
  return value;
}

export function validateExpectedStatus(value: number): number {
  if (!Number.isInteger(value) || value < 100 || value > 599) throw new OpsHavenError("CONFIG_INVALID", "Expected health status is invalid.");
  return value;
}

export function validateHealthUrl(value: string): string {
  let parsed: any;
  try { parsed = new URL(value); }
  catch { throw new OpsHavenError("CONFIG_INVALID", "Health check must be a valid HTTP URL."); }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new OpsHavenError("CONFIG_INVALID", "Health check must be a credential-free HTTP URL without query or fragment data.");
  }
  return parsed.toString();
}

export function validateExactRevision(value: string): string {
  if (!COMMIT_SHA.test(value)) throw new OpsHavenError("INVALID_ARGUMENTS", "Revision must be one complete 40-character Git commit SHA. Branches, tags, HEAD, latest, and abbreviated SHAs are not accepted.");
  return value.toLowerCase();
}

export function safeDeploymentPath(value: string, label: string): string {
  if (!SAFE_PATH.test(value) || !path.isAbsolute(value) || path.normalize(value) !== value || value.includes("..")) {
    throw new OpsHavenError("CONFIG_INVALID", `${label} must be a normalized absolute path.`);
  }
  return value;
}

function resourceId(prefix: string, appId: string): string {
  const value = `${prefix}.${appId}`;
  if (!RESOURCE_ID.test(value)) throw new OpsHavenError("CONFIG_INVALID", "Generated application identity is invalid.");
  return value;
}

function fileDigest(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function deploymentStateRoot(override?: string): string {
  const selected = override ?? process.env.OPSHAVEN_DEPLOYMENT_STATE_ROOT;
  if (selected) return safeDeploymentPath(selected, "Deployment state root");
  const home = homedir();
  if (!home || !path.isAbsolute(home) || path.normalize(home) !== home) throw new OpsHavenError("CONFIG_INVALID", "A local operator home directory could not be determined.");
  return path.join(home, ".config", "opshaven", "deployment");
}

export async function readProtectedDocument(filePath: string, label: string): Promise<ProtectedDocument> {
  let handle: any;
  try { handle = await fs.open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); }
  catch { throw new OpsHavenError("CONFIG_INVALID", `${label} is unavailable or unsafe.`); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.isSymbolicLink?.() || stat.size > 1024 * 1024 || (stat.mode & 0o077) !== 0) throw new OpsHavenError("CONFIG_INVALID", `${label} must be an owner-only regular file.`);
    return { text: await handle.readFile("utf8"), mode: stat.mode & 0o777, dev: stat.dev, ino: stat.ino };
  } finally { await handle.close(); }
}

async function privateTemporary(target: string, text: string): Promise<string> {
  const parent = path.dirname(target);
  await ensurePrivateDirectory(parent, "Operator state directory", "CONFIG_INVALID");
  const temporary = path.join(parent, `.${path.basename(target)}.opshaven-${process.pid}-${randomBytes(8).toString("hex")}`);
  const handle = await fs.open(temporary, "wx", 0o600);
  try { await handle.writeFile(text, "utf8"); await handle.sync(); }
  finally { await handle.close(); }
  return temporary;
}

export async function replaceProtectedDocument(target: string, original: ProtectedDocument, text: string): Promise<void> {
  const current = await fs.lstat(target).catch(() => null);
  if (!current || !current.isFile() || current.isSymbolicLink() || current.dev !== original.dev || current.ino !== original.ino) throw new OpsHavenError("CONFIG_INVALID", "Protected configuration changed during application registration.");
  const temporary = await privateTemporary(target, text);
  try { await fs.chmod(temporary, original.mode); await fs.rename(temporary, target); }
  finally { await fs.rm(temporary, { force: true }); }
}

async function writeOnce(filePath: string, value: unknown): Promise<void> {
  await ensurePrivateDirectory(path.dirname(filePath), "Deployment state directory", "CONFIG_INVALID");
  let handle: any;
  try { handle = await fs.open(filePath, "wx", 0o600); }
  catch (error: any) {
    if (error?.code === "EEXIST") throw new OpsHavenError("POLICY_DENIED", "The protected deployment record already exists.");
    throw new OpsHavenError("CONFIG_INVALID", "Protected deployment state could not be created safely.");
  }
  try { await handle.writeFile(`${canonicalize(value)}\n`, "utf8"); await handle.sync(); }
  catch (error) { await handle.close().catch(() => undefined); await fs.rm(filePath, { force: true }); throw error; }
  await handle.close();
}

async function replacePrivate(filePath: string, value: unknown): Promise<void> {
  const temporary = await privateTemporary(filePath, `${canonicalize(value)}\n`);
  try { await fs.rename(temporary, filePath); }
  finally { await fs.rm(temporary, { force: true }); }
}

async function readPrivateJson(filePath: string, label: string): Promise<unknown> {
  const text = await readRegularTextFile(filePath, label, { ownerOnly: true, maxBytes: 1024 * 1024, code: "CONFIG_INVALID" });
  try { return JSON.parse(text) as unknown; }
  catch { throw new OpsHavenError("CONFIG_INVALID", `${label} is malformed.`); }
}

export function generatedResources(input: ApplicationRegistrationInput, hostId: string): Record<string, unknown>[] {
  const appId = validateApplicationId(input.id);
  validateApplicationName(input.name);
  const repository = safeDeploymentPath(input.repositoryLocation, "Repository location");
  const releases = safeDeploymentPath(input.releaseLocation, "Release location");
  const current = safeDeploymentPath(path.join(path.dirname(releases), "current"), "Current release location");
  if (releases === current || repository === releases || repository.startsWith(`${releases}/`) || releases.startsWith(`${repository}/`) || current === repository || current.startsWith(`${repository}/`)) {
    throw new OpsHavenError("CONFIG_INVALID", "Repository, release, and active-release paths must be distinct non-overlapping locations.");
  }
  const service = validateServiceIdentifier(input.serviceIdentifier);
  const health = validateHealthUrl(input.healthCheckUrl);
  const status = validateExpectedStatus(input.expectedStatus ?? 200);
  return [
    { id: resourceId("app", appId), kind: "application", hostId, runtimeConfigKeys: [] },
    { id: resourceId("service", appId), kind: "service", hostId, unit: service },
    { id: resourceId("probe", appId), kind: "probe", hostId, url: health, method: "GET", expectedStatus: [status], timeoutMs: 5000 },
    {
      id: resourceId("deployment", appId), kind: "deployment", hostId, repositoryPath: repository, releasesPath: releases, currentSymlink: current,
      allowedRefs: ["refs/remotes/origin/main"], activation: "systemd", serviceIds: [resourceId("service", appId)], probeIds: [resourceId("probe", appId)],
      buildSteps: [
        { executable: NPM, args: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd: "release" },
        { executable: NPM, args: ["run", "build"], cwd: "release" },
      ],
      checkSteps: [], fetchBeforeDeploy: false, migrationPolicy: "none",
    },
  ];
}

export function selectDeploymentHost(config: OpsHavenConfig, target: string): HostResource {
  const matches = [...config.resources.values()].filter((item): item is HostResource => item.kind === "host" && (item.id === target || item.address === target));
  if (matches.length !== 1) throw new OpsHavenError("CONFIG_INVALID", "Remote target must identify exactly one configured OpsHaven host.");
  return matches[0] as HostResource;
}

export function configDocument(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new OpsHavenError("CONFIG_INVALID", "Protected configuration is malformed.");
  const document = raw as Record<string, unknown>;
  if (!Array.isArray(document.resources) || typeof document.policyVersion !== "string") throw new OpsHavenError("CONFIG_INVALID", "Protected configuration is malformed.");
  return document;
}

export function nextDeploymentPolicyVersion(current: string, resources: unknown[]): string {
  const base = current.replace(/-apps-[a-f0-9]{12}$/i, "");
  const selected = `${base}-apps-${sha256(resources).slice(0, 12)}`;
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(selected)) throw new OpsHavenError("CONFIG_INVALID", "Generated authorization policy version is invalid.");
  return selected;
}

function buildProfileSupported(target: DeploymentResource): boolean {
  const first = target.buildSteps[0];
  const second = target.buildSteps[1];
  return target.buildSteps.length === 2 && target.checkSteps.length === 0 && !target.fetchBeforeDeploy && target.activation === "systemd" && target.migrationPolicy === "none"
    && first?.executable === NPM && first.cwd === "release" && canonicalize(first.args) === canonicalize(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])
    && second?.executable === NPM && second.cwd === "release" && canonicalize(second.args) === canonicalize(["run", "build"]);
}

function applicationBase(input: ApplicationRegistrationInput, host: HostResource): Omit<DeploymentApplication, "resourceBindingDigest" | "createdAt"> {
  return {
    schemaVersion: 1,
    id: validateApplicationId(input.id), name: validateApplicationName(input.name), targetLabel: input.remoteTarget, hostResourceId: host.id,
    applicationResourceId: resourceId("app", input.id), deploymentResourceId: resourceId("deployment", input.id), serviceResourceId: resourceId("service", input.id), probeResourceId: resourceId("probe", input.id),
    repositoryLocation: safeDeploymentPath(input.repositoryLocation, "Repository location"), releaseLocation: safeDeploymentPath(input.releaseLocation, "Release location"),
    currentReleaseLocation: safeDeploymentPath(path.join(path.dirname(input.releaseLocation), "current"), "Current release location"),
    serviceIdentifier: validateServiceIdentifier(input.serviceIdentifier), healthCheckUrl: validateHealthUrl(input.healthCheckUrl), expectedStatus: validateExpectedStatus(input.expectedStatus ?? 200),
    buildStrategy: DEPLOYMENT_BUILD_STRATEGY, rollbackBehavior: DEPLOYMENT_ROLLBACK_BEHAVIOR,
  };
}

function bindingDigest(config: OpsHavenConfig, app: Omit<DeploymentApplication, "resourceBindingDigest" | "createdAt">): string {
  const ids = [app.hostResourceId, app.applicationResourceId, app.deploymentResourceId, app.serviceResourceId, app.probeResourceId];
  return sha256({ policyVersion: config.policyVersion, resources: ids.map((id) => config.resources.get(id) ?? null), application: app, operationDefinitionsVersion: DEPLOYMENT_OPERATION_VERSION });
}

export function applicationFromConfig(config: OpsHavenConfig, input: ApplicationRegistrationInput, host: HostResource, createdAt: string): DeploymentApplication {
  const base = applicationBase(input, host);
  const binding = applicationBindingUnchecked(config, base);
  if (!buildProfileSupported(binding.deployment)) throw new OpsHavenError("CONFIG_INVALID", "Generated application deployment profile did not pass validation.");
  return { ...base, resourceBindingDigest: bindingDigest(config, base), createdAt };
}

function applicationBindingUnchecked(config: OpsHavenConfig, app: Omit<DeploymentApplication, "resourceBindingDigest" | "createdAt">): { host: HostResource; deployment: DeploymentResource; service: ServiceResource; probe: ProbeResource } {
  const host = config.resources.get(app.hostResourceId);
  const deployment = config.resources.get(app.deploymentResourceId);
  const service = config.resources.get(app.serviceResourceId);
  const probe = config.resources.get(app.probeResourceId);
  if (!host || host.kind !== "host" || !deployment || deployment.kind !== "deployment" || !service || service.kind !== "service" || !probe || probe.kind !== "probe") throw new OpsHavenError("CONFIG_INVALID", "Application authorization binding is missing or outdated.");
  return { host, deployment, service, probe };
}

export function applicationBinding(config: OpsHavenConfig, app: DeploymentApplication): { host: HostResource; deployment: DeploymentResource; service: ServiceResource; probe: ProbeResource } {
  const base: Omit<DeploymentApplication, "resourceBindingDigest" | "createdAt"> = {
    schemaVersion: app.schemaVersion,
    id: app.id,
    name: app.name,
    targetLabel: app.targetLabel,
    hostResourceId: app.hostResourceId,
    applicationResourceId: app.applicationResourceId,
    deploymentResourceId: app.deploymentResourceId,
    serviceResourceId: app.serviceResourceId,
    probeResourceId: app.probeResourceId,
    repositoryLocation: app.repositoryLocation,
    releaseLocation: app.releaseLocation,
    currentReleaseLocation: app.currentReleaseLocation,
    serviceIdentifier: app.serviceIdentifier,
    healthCheckUrl: app.healthCheckUrl,
    expectedStatus: app.expectedStatus,
    buildStrategy: app.buildStrategy,
    rollbackBehavior: app.rollbackBehavior,
  };
  const binding = applicationBindingUnchecked(config, base);
  if (bindingDigest(config, base) !== app.resourceBindingDigest || !buildProfileSupported(binding.deployment)
    || binding.deployment.repositoryPath !== app.repositoryLocation || binding.deployment.releasesPath !== app.releaseLocation || binding.deployment.currentSymlink !== app.currentReleaseLocation
    || canonicalize(binding.deployment.serviceIds) !== canonicalize([binding.service.id]) || canonicalize(binding.deployment.probeIds) !== canonicalize([binding.probe.id])
    || binding.service.unit !== app.serviceIdentifier || binding.probe.url !== app.healthCheckUrl || canonicalize(binding.probe.expectedStatus) !== canonicalize([app.expectedStatus])) {
    throw new OpsHavenError("CONFIG_INVALID", "Application configuration changed after registration.");
  }
  return binding;
}

export async function targetIdentityDigest(host: HostResource): Promise<string> {
  const knownHosts = await readRegularFile(host.knownHostsFile, "Pinned host identity", { maxBytes: 1024 * 1024, code: "CONFIG_INVALID" });
  const identity = await readRegularFile(host.identityFile, "Restricted SSH identity", { ownerOnly: true, maxBytes: 1024 * 1024, code: "CONFIG_INVALID" });
  return sha256({ host: { id: host.id, address: host.address, port: host.port, user: host.user }, knownHostsDigest: fileDigest(knownHosts), identityDigest: fileDigest(identity) });
}

export async function operatorProfileDigest(config: OpsHavenConfig): Promise<string> {
  const publicKey = await readRegularFile(config.approvals.verificationPublicKeyFile, "Approval verification key", { maxBytes: 65536, code: "APPROVAL_INVALID" });
  return sha256({ policyVersion: config.policyVersion, verificationKeyDigest: fileDigest(publicKey) });
}

export function operationDefinitionsDigest(config: OpsHavenConfig, app: DeploymentApplication): string {
  const binding = applicationBinding(config, app);
  return sha256({ version: DEPLOYMENT_OPERATION_VERSION, limits: config.limits, deployment: binding.deployment, service: binding.service, probe: binding.probe });
}

export function availableDiskBytes(rootFilesystem: unknown): number {
  if (typeof rootFilesystem !== "string") return 0;
  const parts = rootFilesystem.trim().split(/\s+/);
  const blocks = parts.length >= 5 ? Number(parts[3]) : 0;
  return Number.isFinite(blocks) && blocks >= 0 ? Math.floor(blocks * 1024) : 0;
}

export function dataOf(result: ResultEnvelope, operation: string): Record<string, unknown> {
  if (!result.ok || !result.data) throw new OpsHavenError("REMOTE_OPERATION_FAILED", result.error?.message ?? `${operation} failed safely.`, result.error?.retryable ?? false);
  return result.data;
}

export function observedFingerprint(value: ObservedDeploymentState): string { return sha256(value); }

export function deploymentOperations(config: OpsHavenConfig, app: DeploymentApplication, revision: string): DeploymentOperation[] {
  const outputBound = { maxBytes: config.limits.maxBytes, maxLines: config.limits.maxLines };
  const create = (kind: DeploymentOperationKind, resources: readonly string[], privilege: DeploymentOperation["requiredPrivilege"], mutation: DeploymentOperation["mutation"], verification: string, rollback: string | null, inputs: Readonly<Record<string, string | number | boolean>> = {}): DeploymentOperation => ({
    kind, inputs, permittedResources: resources, requiredPrivilege: privilege, timeoutMs: config.limits.timeoutMs, outputBound,
    redaction: kind === "build_release" ? "bounded-redacted-output" : "structured-only", mutation, verification, rollback,
  });
  return [
    create("verify_revision", [app.deploymentResourceId], "restricted-remote-user", "none", "Exact commit belongs to the configured source.", null, { revision }),
    create("inspect_current_release", [app.deploymentResourceId], "restricted-remote-user", "none", "Active release matches observed state.", null),
    create("check_disk_space", [app.hostResourceId], "restricted-remote-user", "none", "Available space remains above the minimum.", null, { minimumBytes: DEPLOYMENT_MINIMUM_DISK_BYTES }),
    create("prepare_release", [app.deploymentResourceId], "restricted-remote-user", "release-state", "A new safe versioned release is prepared.", "Remove incomplete non-active release."),
    create("fetch_verified_source", [app.deploymentResourceId], "restricted-remote-user", "release-state", "Prepared source is the exact commit.", "Remove incomplete release."),
    create("build_release", [app.deploymentResourceId], "restricted-remote-user", "release-state", "Only fixed bounded build steps run.", "Remove incomplete release."),
    create("record_rollback_point", [app.deploymentResourceId], "restricted-remote-user", "release-state", "Previous active release remains available.", "Keep previous release active."),
    create("activate_release", [app.deploymentResourceId], "restricted-remote-user", "release-state", "Atomic switch selects only verified release.", "Restore previous release."),
    create("restart_service", [app.serviceResourceId], "approved-systemd-restart", "service-state", "Only approved unit restarts.", "Restart same unit after restore."),
    create("run_health_check", [app.probeResourceId], "restricted-remote-user", "none", "Bounded HTTP check passes.", "Restore and recheck previous release."),
    create("confirm_revision", [app.deploymentResourceId], "restricted-remote-user", "none", "Exact target revision is active.", "Restore and confirm previous revision."),
  ];
}

export function rollbackOperations(config: OpsHavenConfig, app: DeploymentApplication, revision: string): DeploymentOperation[] {
  const operations = deploymentOperations(config, app, revision);
  const find = (kind: DeploymentOperationKind): DeploymentOperation => operations.find((item) => item.kind === kind) as DeploymentOperation;
  return [{ ...find("activate_release"), kind: "restore_release", verification: "Previous release becomes active atomically.", rollback: null }, find("restart_service"), find("run_health_check"), find("confirm_revision")];
}

export function deploymentPlanId(plan: DeploymentPlan): string { return `sha256:${sha256(plan)}`; }

function assertApplication(value: unknown): DeploymentApplication {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("CONFIG_INVALID", "Application registration is malformed.");
  const app = value as Record<string, unknown>;
  if (app.schemaVersion !== 1 || typeof app.id !== "string" || !APP_ID.test(app.id) || typeof app.name !== "string" || !APP_NAME.test(app.name)
    || typeof app.resourceBindingDigest !== "string" || !/^[a-f0-9]{64}$/.test(app.resourceBindingDigest) || typeof app.createdAt !== "string" || !Number.isFinite(Date.parse(app.createdAt))) {
    throw new OpsHavenError("CONFIG_INVALID", "Application registration is malformed.");
  }
  return app as unknown as DeploymentApplication;
}

function assertPlan(value: unknown): DeploymentPlan {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new OpsHavenError("CONFIG_INVALID", "Stored deployment plan is malformed.");
  const plan = value as Record<string, unknown>;
  if (plan.schemaVersion !== 1 || typeof plan.applicationId !== "string" || !APP_ID.test(plan.applicationId)
    || typeof plan.currentRevision !== "string" || !COMMIT_SHA.test(plan.currentRevision) || typeof plan.targetRevision !== "string" || !COMMIT_SHA.test(plan.targetRevision)
    || typeof plan.observedStateFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(plan.observedStateFingerprint)
    || typeof plan.applicationConfigDigest !== "string" || !/^[a-f0-9]{64}$/.test(plan.applicationConfigDigest)
    || typeof plan.operationDefinitionsDigest !== "string" || !/^[a-f0-9]{64}$/.test(plan.operationDefinitionsDigest)
    || typeof plan.createdAt !== "string" || !Number.isFinite(Date.parse(plan.createdAt)) || typeof plan.expiresAt !== "string" || !Number.isFinite(Date.parse(plan.expiresAt))
    || typeof plan.nonce !== "string" || !NONCE.test(plan.nonce) || !Array.isArray(plan.operations)) throw new OpsHavenError("CONFIG_INVALID", "Stored deployment plan is malformed.");
  return plan as unknown as DeploymentPlan;
}

export class DeploymentRegistry {
  readonly root: string;
  constructor(root?: string) { this.root = deploymentStateRoot(root); }
  private directory(): string { return path.join(this.root, "applications"); }
  private file(id: string): string { return path.join(this.directory(), `${validateApplicationId(id)}.json`); }
  async get(id: string): Promise<DeploymentApplication> { return assertApplication(await readPrivateJson(this.file(id), "Application registration")); }
  async list(): Promise<DeploymentApplication[]> {
    await ensurePrivateDirectory(this.directory(), "Application registry", "CONFIG_INVALID");
    const output: DeploymentApplication[] = [];
    for (const name of (await fs.readdir(this.directory())).sort()) if (/^[a-z][a-z0-9-]{0,47}\.json$/.test(name)) output.push(assertApplication(await readPrivateJson(path.join(this.directory(), name), "Application registration")));
    return output;
  }
  async create(app: DeploymentApplication): Promise<void> { await writeOnce(this.file(app.id), app); }
  async remove(id: string): Promise<void> { await fs.rm(this.file(id), { force: true }); }
}

export class DeploymentPlanStore {
  readonly root: string;
  constructor(root?: string) { this.root = deploymentStateRoot(root); }
  private digest(planId: string): string {
    const match = PLAN_ID.exec(planId);
    if (!match?.[1]) throw new OpsHavenError("INVALID_ARGUMENTS", "Plan ID must use sha256:<digest> format.");
    return match[1];
  }
  private planFile(planId: string): string { return path.join(this.root, "plans", `${this.digest(planId)}.json`); }
  private indexFile(key: string): string { return path.join(this.root, "plan-index", `${key}.json`); }
  startFile(planId: string): string { return path.join(this.root, "executions", `${this.digest(planId)}.started.json`); }
  resultFile(planId: string): string { return path.join(this.root, "executions", `${this.digest(planId)}.result.json`); }
  lockFile(appId: string): string { return path.join(this.root, "locks", `${validateApplicationId(appId)}.lock`); }
  async save(plan: DeploymentPlan): Promise<StoredDeploymentPlan> { const planId = deploymentPlanId(plan); await writeOnce(this.planFile(planId), { planId, plan }); return { planId, plan }; }
  async load(planId: string): Promise<StoredDeploymentPlan> {
    const raw = await readPrivateJson(this.planFile(planId), "Deployment plan");
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new OpsHavenError("CONFIG_INVALID", "Stored deployment plan is malformed.");
    const item = raw as Record<string, unknown>;
    const plan = assertPlan(item.plan);
    if (item.planId !== planId || deploymentPlanId(plan) !== planId) throw new OpsHavenError("POLICY_DENIED", "Deployment plan digest mismatch. No changes were made.");
    return { planId, plan };
  }
  async reusable(key: string, now: number): Promise<StoredDeploymentPlan | null> {
    if (!/^[a-f0-9]{64}$/.test(key)) return null;
    try {
      const raw = await readPrivateJson(this.indexFile(key), "Deployment plan index") as Record<string, unknown>;
      const stored = typeof raw?.planId === "string" ? await this.load(raw.planId) : null;
      return stored && Date.parse(stored.plan.expiresAt) > now ? stored : null;
    } catch { return null; }
  }
  async index(key: string, planId: string): Promise<void> { await replacePrivate(this.indexFile(key), { schemaVersion: 1, planId }); }
  async markStarted(record: ExecutionStart): Promise<void> { await writeOnce(this.startFile(record.planId), record); }
  async markResult(record: ExecutionResultRecord): Promise<void> { await writeOnce(this.resultFile(record.planId), record); }
  async replayed(planId: string): Promise<boolean> { try { await fs.lstat(this.startFile(planId)); return true; } catch (error: any) { if (error?.code === "ENOENT") return false; throw error; } }
  async acquireApplicationLock(appId: string, value: unknown): Promise<() => Promise<void>> {
    const file = this.lockFile(appId);
    await ensurePrivateDirectory(path.dirname(file), "Deployment lock directory", "CONFIG_INVALID");
    let handle: any;
    try { handle = await fs.open(file, "wx", 0o600); }
    catch (error: any) { if (error?.code === "EEXIST") throw new OpsHavenError("POLICY_DENIED", "Another deployment or unresolved recovery state already holds this application lock."); throw error; }
    await handle.writeFile(`${canonicalize(value)}\n`, "utf8"); await handle.sync(); await handle.close();
    return async () => { await fs.rm(file, { force: true }); };
  }
}
