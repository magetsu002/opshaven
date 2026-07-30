import { promises as fs } from "node:fs";
import path from "node:path";
import { assertPlainObject, rejectUnknownKeys } from "./canonical.js";
import { OpsHavenError } from "./errors.js";

export type ResourceKind =
  | "host"
  | "application"
  | "service"
  | "container"
  | "deployment"
  | "proxy"
  | "probe"
  | "database"
  | "monitoring"
  | "backup";

interface BaseResource { id: string; kind: ResourceKind; hostId?: string }
export interface HostResource extends BaseResource {
  kind: "host";
  address: string;
  port: number;
  user: string;
  knownHostsFile: string;
  identityFile: string;
  connectTimeoutMs: number;
}
export interface ApplicationResource extends BaseResource {
  kind: "application";
  hostId: string;
  runtimeConfigKeys: string[];
  environmentFile?: string;
}
export interface ServiceResource extends BaseResource {
  kind: "service";
  hostId: string;
  unit: string;
}
export interface ContainerResource extends BaseResource {
  kind: "container";
  hostId: string;
  runtime: "docker";
  container: string;
}
export interface TrustedStep { executable: string; args: string[]; cwd: "release" | "repository" }
export interface DeploymentResource extends BaseResource {
  kind: "deployment";
  hostId: string;
  repositoryPath: string;
  releasesPath: string;
  currentSymlink: string;
  allowedRefs: string[];
  activation: "systemd" | "compose";
  serviceIds: string[];
  probeIds: string[];
  buildSteps: TrustedStep[];
  checkSteps: TrustedStep[];
  fetchBeforeDeploy: boolean;
  migrationPolicy: "none" | "manual";
}
export interface ProxyResource extends BaseResource {
  kind: "proxy";
  hostId: string;
  provider: "nginx" | "caddy";
  serviceId: string;
  publicNames: string[];
}
export interface ProbeResource extends BaseResource {
  kind: "probe";
  hostId: string;
  url: string;
  method: "GET" | "HEAD";
  expectedStatus: number[];
  timeoutMs: number;
}
export interface DatabaseResource extends BaseResource {
  kind: "database";
  hostId: string;
  engine: "postgresql" | "mysql" | "sqlite";
  migrationPolicy: "none" | "manual";
}
export interface MonitoringResource extends BaseResource {
  kind: "monitoring";
  hostId: string;
  serviceIds: string[];
  probeIds: string[];
}
export interface BackupResource extends BaseResource {
  kind: "backup";
  hostId: string;
  statusFile: string;
  maximumAgeHours: number;
}

export type Resource = HostResource | ApplicationResource | ServiceResource | ContainerResource | DeploymentResource | ProxyResource | ProbeResource | DatabaseResource | MonitoringResource | BackupResource;

export interface LimitsConfig {
  timeoutMs: number;
  maxBytes: number;
  maxLines: number;
}
export interface AuditConfig { path: string }
export interface ApprovalConfig { directory: string; secretFile: string; signingPrivateKeyFile: string; verificationPublicKeyFile: string; remoteUsedDirectory: string; defaultTtlSeconds: number }
export interface OpsHavenConfig {
  version: 1;
  policyVersion: string;
  limits: LimitsConfig;
  audit: AuditConfig;
  approvals: ApprovalConfig;
  secretFingerprints: string[];
  resources: ReadonlyMap<string, Resource>;
}

const ID = /^[a-z][a-z0-9._-]{0,63}$/;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,127}$/;
const SAFE_REF = /^(?!-)(?!.*\.\.)(?!.*\/\/)[A-Za-z0-9._/-]{1,160}$/;
const ABSOLUTE_SAFE_PATH = /^\/(?:[A-Za-z0-9._-]+\/?)+$/;

function text(value: unknown, label: string, pattern?: RegExp): string {
  if (typeof value !== "string" || value.length === 0 || (pattern && !pattern.test(value))) throw new OpsHavenError("CONFIG_INVALID", `${label} is invalid.`);
  return value;
}
function integer(value: unknown, label: string, min: number, max: number): number {
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) throw new OpsHavenError("CONFIG_INVALID", `${label} is invalid.`);
  return value as number;
}
function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new OpsHavenError("CONFIG_INVALID", `${label} must be boolean.`);
  return value;
}
function stringArray(value: unknown, label: string, pattern: RegExp, max = 64): string[] {
  if (!Array.isArray(value) || value.length > max) throw new OpsHavenError("CONFIG_INVALID", `${label} must be a bounded array.`);
  const result = value.map((item, index) => text(item, `${label}[${index}]`, pattern));
  if (new Set(result).size !== result.length) throw new OpsHavenError("CONFIG_INVALID", `${label} contains duplicates.`);
  return result;
}
function safePath(value: unknown, label: string): string {
  const result = text(value, label, ABSOLUTE_SAFE_PATH);
  if (result.includes("..") || path.normalize(result) !== result) throw new OpsHavenError("CONFIG_INVALID", `${label} must be a normalized absolute path.`);
  return result;
}
function hostId(value: unknown, label: string): string { return text(value, label, ID); }

function parseStep(value: unknown, label: string): TrustedStep {
  assertPlainObject(value, label);
  rejectUnknownKeys(value, ["executable", "args", "cwd"], label);
  const cwd = text(value.cwd, `${label}.cwd`);
  if (cwd !== "release" && cwd !== "repository") throw new OpsHavenError("CONFIG_INVALID", `${label}.cwd is invalid.`);
  const args = stringArray(value.args, `${label}.args`, /^[A-Za-z0-9_./:=+@{},-]{0,256}$/, 32);
  return { executable: safePath(value.executable, `${label}.executable`), args, cwd };
}

function parseResource(value: unknown, index: number): Resource {
  const label = `resources[${index}]`;
  assertPlainObject(value, label);
  const id = text(value.id, `${label}.id`, ID);
  const kind = text(value.kind, `${label}.kind`) as ResourceKind;
  const common = { id, kind };
  switch (kind) {
    case "host":
      rejectUnknownKeys(value, ["id", "kind", "address", "port", "user", "knownHostsFile", "identityFile", "connectTimeoutMs"], label);
      return { ...common, kind, address: text(value.address, `${label}.address`, /^[A-Za-z0-9.-]{1,253}$/), port: integer(value.port, `${label}.port`, 1, 65535), user: text(value.user, `${label}.user`, /^[a-z_][a-z0-9_-]{0,31}$/), knownHostsFile: safePath(value.knownHostsFile, `${label}.knownHostsFile`), identityFile: safePath(value.identityFile, `${label}.identityFile`), connectTimeoutMs: integer(value.connectTimeoutMs, `${label}.connectTimeoutMs`, 1000, 60000) };
    case "application":
      rejectUnknownKeys(value, ["id", "kind", "hostId", "runtimeConfigKeys", "environmentFile"], label);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), runtimeConfigKeys: stringArray(value.runtimeConfigKeys, `${label}.runtimeConfigKeys`, /^[A-Z][A-Z0-9_]{0,127}$/), ...(value.environmentFile === undefined ? {} : { environmentFile: safePath(value.environmentFile, `${label}.environmentFile`) }) };
    case "service":
      rejectUnknownKeys(value, ["id", "kind", "hostId", "unit"], label);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), unit: text(value.unit, `${label}.unit`, SAFE_NAME) };
    case "container":
      rejectUnknownKeys(value, ["id", "kind", "hostId", "runtime", "container"], label);
      if (value.runtime !== "docker") throw new OpsHavenError("CONFIG_INVALID", `${label}.runtime is invalid.`);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), runtime: "docker", container: text(value.container, `${label}.container`, SAFE_NAME) };
    case "deployment": {
      rejectUnknownKeys(value, ["id", "kind", "hostId", "repositoryPath", "releasesPath", "currentSymlink", "allowedRefs", "activation", "serviceIds", "probeIds", "buildSteps", "checkSteps", "fetchBeforeDeploy", "migrationPolicy"], label);
      const activation = text(value.activation, `${label}.activation`);
      const migrationPolicy = text(value.migrationPolicy, `${label}.migrationPolicy`);
      if (activation !== "systemd" && activation !== "compose") throw new OpsHavenError("CONFIG_INVALID", `${label}.activation is invalid.`);
      if (migrationPolicy !== "none" && migrationPolicy !== "manual") throw new OpsHavenError("CONFIG_INVALID", `${label}.migrationPolicy is invalid.`);
      if (!Array.isArray(value.buildSteps) || !Array.isArray(value.checkSteps)) throw new OpsHavenError("CONFIG_INVALID", `${label} steps must be arrays.`);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), repositoryPath: safePath(value.repositoryPath, `${label}.repositoryPath`), releasesPath: safePath(value.releasesPath, `${label}.releasesPath`), currentSymlink: safePath(value.currentSymlink, `${label}.currentSymlink`), allowedRefs: stringArray(value.allowedRefs, `${label}.allowedRefs`, SAFE_REF), activation, serviceIds: stringArray(value.serviceIds, `${label}.serviceIds`, ID), probeIds: stringArray(value.probeIds, `${label}.probeIds`, ID), buildSteps: value.buildSteps.map((step, stepIndex) => parseStep(step, `${label}.buildSteps[${stepIndex}]`)), checkSteps: value.checkSteps.map((step, stepIndex) => parseStep(step, `${label}.checkSteps[${stepIndex}]`)), fetchBeforeDeploy: boolean(value.fetchBeforeDeploy, `${label}.fetchBeforeDeploy`), migrationPolicy };
    }
    case "proxy": {
      rejectUnknownKeys(value, ["id", "kind", "hostId", "provider", "serviceId", "publicNames"], label);
      const provider = text(value.provider, `${label}.provider`);
      if (provider !== "nginx" && provider !== "caddy") throw new OpsHavenError("CONFIG_INVALID", `${label}.provider is invalid.`);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), provider, serviceId: text(value.serviceId, `${label}.serviceId`, ID), publicNames: stringArray(value.publicNames, `${label}.publicNames`, /^[A-Za-z0-9.-]{1,253}$/) };
    }
    case "probe": {
      rejectUnknownKeys(value, ["id", "kind", "hostId", "url", "method", "expectedStatus", "timeoutMs"], label);
      const url = text(value.url, `${label}.url`);
      let parsed: URL;
      try { parsed = new URL(url); }
      catch { throw new OpsHavenError("CONFIG_INVALID", `${label}.url is invalid.`); }
      if (!(parsed.protocol === "http:" || parsed.protocol === "https:") || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash) throw new OpsHavenError("CONFIG_INVALID", `${label}.url must be a credential-free HTTP(S) URL without query or fragment data.`);
      const method = text(value.method, `${label}.method`);
      if (method !== "GET" && method !== "HEAD") throw new OpsHavenError("CONFIG_INVALID", `${label}.method is invalid.`);
      if (!Array.isArray(value.expectedStatus)) throw new OpsHavenError("CONFIG_INVALID", `${label}.expectedStatus must be an array.`);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), url, method, expectedStatus: value.expectedStatus.map((status, statusIndex) => integer(status, `${label}.expectedStatus[${statusIndex}]`, 100, 599)), timeoutMs: integer(value.timeoutMs, `${label}.timeoutMs`, 100, 60000) };
    }
    case "database": {
      rejectUnknownKeys(value, ["id", "kind", "hostId", "engine", "migrationPolicy"], label);
      const engine = text(value.engine, `${label}.engine`);
      const migrationPolicy = text(value.migrationPolicy, `${label}.migrationPolicy`);
      if (!(engine === "postgresql" || engine === "mysql" || engine === "sqlite")) throw new OpsHavenError("CONFIG_INVALID", `${label}.engine is invalid.`);
      if (!(migrationPolicy === "none" || migrationPolicy === "manual")) throw new OpsHavenError("CONFIG_INVALID", `${label}.migrationPolicy is invalid.`);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), engine, migrationPolicy };
    }
    case "monitoring":
      rejectUnknownKeys(value, ["id", "kind", "hostId", "serviceIds", "probeIds"], label);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), serviceIds: stringArray(value.serviceIds, `${label}.serviceIds`, ID), probeIds: stringArray(value.probeIds, `${label}.probeIds`, ID) };
    case "backup":
      rejectUnknownKeys(value, ["id", "kind", "hostId", "statusFile", "maximumAgeHours"], label);
      return { ...common, kind, hostId: hostId(value.hostId, `${label}.hostId`), statusFile: safePath(value.statusFile, `${label}.statusFile`), maximumAgeHours: integer(value.maximumAgeHours, `${label}.maximumAgeHours`, 1, 8760) };
    default:
      throw new OpsHavenError("CONFIG_INVALID", `${label}.kind is unknown.`);
  }
}

function requireReference(resources: Map<string, Resource>, owner: Resource, id: string, kind: "service" | "probe"): Resource {
  const referenced = resources.get(id);
  if (!referenced || referenced.kind !== kind || referenced.hostId !== owner.hostId) throw new OpsHavenError("CONFIG_INVALID", `${owner.id} references an invalid ${kind} ${id}.`);
  return referenced;
}

function validateReferences(resources: Map<string, Resource>): void {
  for (const resource of resources.values()) {
    if (resource.kind !== "host") {
      const host = resources.get(resource.hostId);
      if (!host || host.kind !== "host") throw new OpsHavenError("CONFIG_INVALID", `${resource.id} references an unknown host.`);
    }
    if (resource.kind === "deployment" || resource.kind === "monitoring") {
      for (const id of resource.serviceIds) requireReference(resources, resource, id, "service");
      for (const id of resource.probeIds) requireReference(resources, resource, id, "probe");
    }
    if (resource.kind === "proxy") requireReference(resources, resource, resource.serviceId, "service");
  }
}

export function parseConfig(raw: unknown): OpsHavenConfig {
  assertPlainObject(raw, "config");
  rejectUnknownKeys(raw, ["version", "policyVersion", "limits", "audit", "approvals", "secretFingerprints", "resources"], "config");
  if (raw.version !== 1) throw new OpsHavenError("CONFIG_INVALID", "Only configuration version 1 is supported.");
  assertPlainObject(raw.limits, "limits");
  rejectUnknownKeys(raw.limits, ["timeoutMs", "maxBytes", "maxLines"], "limits");
  assertPlainObject(raw.audit, "audit");
  rejectUnknownKeys(raw.audit, ["path"], "audit");
  assertPlainObject(raw.approvals, "approvals");
  rejectUnknownKeys(raw.approvals, ["directory", "secretFile", "signingPrivateKeyFile", "verificationPublicKeyFile", "remoteUsedDirectory", "defaultTtlSeconds"], "approvals");
  if (!Array.isArray(raw.resources) || raw.resources.length === 0 || raw.resources.length > 512) throw new OpsHavenError("CONFIG_INVALID", "resources must be a non-empty bounded array.");
  const resources = new Map<string, Resource>();
  raw.resources.forEach((item, index) => {
    const resource = parseResource(item, index);
    if (resources.has(resource.id)) throw new OpsHavenError("CONFIG_INVALID", `Duplicate resource ID ${resource.id}.`);
    resources.set(resource.id, resource);
  });
  validateReferences(resources);
  return {
    version: 1,
    policyVersion: text(raw.policyVersion, "policyVersion", /^[A-Za-z0-9._-]{1,64}$/),
    limits: { timeoutMs: integer(raw.limits.timeoutMs, "limits.timeoutMs", 100, 120000), maxBytes: integer(raw.limits.maxBytes, "limits.maxBytes", 1024, 1048576), maxLines: integer(raw.limits.maxLines, "limits.maxLines", 1, 5000) },
    audit: { path: safePath(raw.audit.path, "audit.path") },
    approvals: { directory: safePath(raw.approvals.directory, "approvals.directory"), secretFile: safePath(raw.approvals.secretFile, "approvals.secretFile"), signingPrivateKeyFile: safePath(raw.approvals.signingPrivateKeyFile, "approvals.signingPrivateKeyFile"), verificationPublicKeyFile: safePath(raw.approvals.verificationPublicKeyFile, "approvals.verificationPublicKeyFile"), remoteUsedDirectory: safePath(raw.approvals.remoteUsedDirectory, "approvals.remoteUsedDirectory"), defaultTtlSeconds: integer(raw.approvals.defaultTtlSeconds, "approvals.defaultTtlSeconds", 30, 3600) },
    secretFingerprints: stringArray(raw.secretFingerprints, "secretFingerprints", /^[a-f0-9]{8,128}$/i, 128),
    resources,
  };
}

export async function loadConfig(filePath: string): Promise<OpsHavenConfig> {
  const stats = await fs.lstat(filePath);
  if (stats.isSymbolicLink() || !stats.isFile()) throw new OpsHavenError("CONFIG_INVALID", "Configuration path must be a regular non-symlink file.");
  const raw = JSON.parse(await fs.readFile(filePath, "utf8")) as unknown;
  return parseConfig(raw);
}
