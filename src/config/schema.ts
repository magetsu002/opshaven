import { OpsHavenError } from "../core/errors.js";
import type { OutputBounds } from "../core/types.js";

export type CommandStep = Readonly<{
  executable: "npm" | "pnpm" | "yarn" | "node" | "docker";
  args: readonly string[];
  timeoutMs: number;
}>;

export type HostConfig = Readonly<{
  id: string;
  address: string;
  port: number;
  username: string;
  identityFile: string;
  knownHostsFile: string;
  hostKeySha256: string;
  dispatcherCommand: "opshaven-dispatch";
}>;

export type ApplicationConfig = Readonly<{
  id: string;
  hostId: string;
  displayName: string;
}>;

export type ServiceConfig = Readonly<{
  id: string;
  hostId: string;
  applicationId: string;
  unit: string;
  restartAllowed: boolean;
  runtimeEnvFile?: string;
  requiredEnvironment: readonly string[];
}>;

export type ContainerConfig = Readonly<{
  id: string;
  hostId: string;
  applicationId: string;
  engine: "docker";
  containerName: string;
}>;

export type ProbeConfig = Readonly<{
  id: string;
  hostId: string;
  url: string;
  expectedStatus: readonly number[];
  timeoutMs: number;
}>;

export type ProxyConfig = Readonly<{
  id: string;
  hostId: string;
  provider: "nginx" | "caddy";
  serviceId: string;
  routes: readonly Readonly<{ hostname: string; pathPrefix: string; upstreamId: string }>[];
}>;

export type DatabaseConfig = Readonly<{
  id: string;
  hostId: string;
  engine: "postgresql" | "mysql" | "sqlite";
  serviceId?: string;
  evidencePath?: string;
}>;

export type MonitoringConfig = Readonly<{
  id: string;
  hostId: string;
  serviceIds: readonly string[];
}>;

export type BackupConfig = Readonly<{
  id: string;
  hostId: string;
  provider: "file-marker";
  evidencePath: string;
  restoreProcedurePath: string;
  maximumAgeSeconds: number;
}>;

export type DeploymentConfig = Readonly<{
  id: string;
  hostId: string;
  applicationId: string;
  repositoryPath: string;
  releasesPath: string;
  activeSymlink: string;
  stateFile: string;
  allowedRefs: readonly string[];
  strategy: "systemd" | "docker-compose";
  serviceIds: readonly string[];
  probeIds: readonly string[];
  checkSteps: readonly CommandStep[];
  buildSteps: readonly CommandStep[];
  migrationRisk: "none" | "manual-review";
}>;

export type SecretRuleConfig = Readonly<{
  fingerprints: readonly string[];
  keyNames: readonly string[];
}>;

export type OpsHavenConfig = Readonly<{
  version: 1;
  policyVersion: string;
  defaults: Readonly<{ timeoutMs: number; output: OutputBounds }>;
  audit: Readonly<{ path: string }>;
  approvals: Readonly<{ stateDirectory: string; ttlSeconds: number; keyEnvironmentVariable: string }>;
  secrets: SecretRuleConfig;
  hosts: readonly HostConfig[];
  applications: readonly ApplicationConfig[];
  services: readonly ServiceConfig[];
  containers: readonly ContainerConfig[];
  deployments: readonly DeploymentConfig[];
  proxies: readonly ProxyConfig[];
  probes: readonly ProbeConfig[];
  databases: readonly DatabaseConfig[];
  monitoring: readonly MonitoringConfig[];
  backups: readonly BackupConfig[];
}>;

type JsonObject = Record<string, unknown>;

const ID = /^[a-z][a-z0-9_-]{1,63}$/;
const UNIT = /^[a-zA-Z0-9@_.:-]{1,128}\.service$/;
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,127}$/;
const SHA256_FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{20,64}$/;
const SAFE_REF = /^(refs\/(heads|tags)\/)?[A-Za-z0-9._/-]{1,200}$/;
const SAFE_STEP_ARG = /^[A-Za-z0-9@%_+=:,./-]{1,240}$/;

function object(value: unknown, context: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OpsHavenError("CONFIG_INVALID", `${context} must be an object`);
  }
  return value as JsonObject;
}

function exact(value: JsonObject, allowed: readonly string[], context: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new OpsHavenError("CONFIG_INVALID", `${context} contains unknown fields`, { fields: unknown });
  }
}

function string(value: unknown, context: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new OpsHavenError("CONFIG_INVALID", `${context} must be a non-empty string`);
  }
  return value;
}

function integer(value: unknown, context: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new OpsHavenError("CONFIG_INVALID", `${context} must be an integer from ${minimum} to ${maximum}`);
  }
  return value as number;
}

function boolean(value: unknown, context: string): boolean {
  if (typeof value !== "boolean") throw new OpsHavenError("CONFIG_INVALID", `${context} must be boolean`);
  return value;
}

function array(value: unknown, context: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new OpsHavenError("CONFIG_INVALID", `${context} must be an array`);
  return value;
}

function id(value: unknown, context: string): string {
  const parsed = string(value, context);
  if (!ID.test(parsed)) throw new OpsHavenError("CONFIG_INVALID", `${context} is not a valid logical ID`);
  return parsed;
}

function absolutePath(value: unknown, context: string): string {
  const parsed = string(value, context);
  if (!parsed.startsWith("/") || parsed.includes("\0") || parsed.split("/").includes("..")) {
    throw new OpsHavenError("CONFIG_INVALID", `${context} must be a normalized absolute path`);
  }
  return parsed;
}

function uniqueIds<T extends { id: string }>(items: readonly T[], context: string): void {
  const seen = new Set<string>();
  for (const item of items) {
    if (seen.has(item.id)) throw new OpsHavenError("CONFIG_INVALID", `Duplicate ${context} ID`, { id: item.id });
    seen.add(item.id);
  }
}

function stringList(value: unknown, context: string, parser: (item: unknown, itemContext: string) => string): string[] {
  return array(value, context).map((item, index) => parser(item, `${context}[${index}]`));
}

function parseHost(value: unknown, index: number): HostConfig {
  const context = `hosts[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "address", "port", "username", "identityFile", "knownHostsFile", "hostKeySha256", "dispatcherCommand"], context);
  const fingerprint = string(item.hostKeySha256, `${context}.hostKeySha256`);
  if (!SHA256_FINGERPRINT.test(fingerprint)) {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.hostKeySha256 must be an SHA256 fingerprint`);
  }
  if (item.dispatcherCommand !== "opshaven-dispatch") {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.dispatcherCommand must be opshaven-dispatch`);
  }
  return {
    id: id(item.id, `${context}.id`),
    address: string(item.address, `${context}.address`),
    port: integer(item.port, `${context}.port`, 1, 65535),
    username: string(item.username, `${context}.username`),
    identityFile: absolutePath(item.identityFile, `${context}.identityFile`),
    knownHostsFile: absolutePath(item.knownHostsFile, `${context}.knownHostsFile`),
    hostKeySha256: fingerprint,
    dispatcherCommand: "opshaven-dispatch"
  };
}

function parseApplication(value: unknown, index: number): ApplicationConfig {
  const context = `applications[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "hostId", "displayName"], context);
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    displayName: string(item.displayName, `${context}.displayName`)
  };
}

function parseService(value: unknown, index: number): ServiceConfig {
  const context = `services[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "hostId", "applicationId", "unit", "restartAllowed", "runtimeEnvFile", "requiredEnvironment"], context);
  const unit = string(item.unit, `${context}.unit`);
  if (!UNIT.test(unit)) throw new OpsHavenError("CONFIG_INVALID", `${context}.unit must be a systemd service unit`);
  const runtimeEnvFile = item.runtimeEnvFile === undefined ? undefined : absolutePath(item.runtimeEnvFile, `${context}.runtimeEnvFile`);
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    applicationId: id(item.applicationId, `${context}.applicationId`),
    unit,
    restartAllowed: boolean(item.restartAllowed, `${context}.restartAllowed`),
    ...(runtimeEnvFile === undefined ? {} : { runtimeEnvFile }),
    requiredEnvironment: stringList(item.requiredEnvironment, `${context}.requiredEnvironment`, (entry, entryContext) => {
      const name = string(entry, entryContext);
      if (!ENV_NAME.test(name)) throw new OpsHavenError("CONFIG_INVALID", `${entryContext} is not an environment key`);
      return name;
    })
  };
}

function parseContainer(value: unknown, index: number): ContainerConfig {
  const context = `containers[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "hostId", "applicationId", "engine", "containerName"], context);
  if (item.engine !== "docker") throw new OpsHavenError("CONFIG_INVALID", `${context}.engine must be docker`);
  const containerName = string(item.containerName, `${context}.containerName`);
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(containerName)) {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.containerName is invalid`);
  }
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    applicationId: id(item.applicationId, `${context}.applicationId`),
    engine: "docker",
    containerName
  };
}

function parseProbe(value: unknown, index: number): ProbeConfig {
  const context = `probes[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "hostId", "url", "expectedStatus", "timeoutMs"], context);
  const parsedUrl = new URL(string(item.url, `${context}.url`));
  if (!["http:", "https:"].includes(parsedUrl.protocol) || parsedUrl.username || parsedUrl.password || parsedUrl.search) {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.url must be HTTP(S) without credentials or query data`);
  }
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    url: parsedUrl.toString(),
    expectedStatus: array(item.expectedStatus, `${context}.expectedStatus`).map((entry, statusIndex) =>
      integer(entry, `${context}.expectedStatus[${statusIndex}]`, 100, 599)
    ),
    timeoutMs: integer(item.timeoutMs, `${context}.timeoutMs`, 100, 30_000)
  };
}

function parseProxy(value: unknown, index: number): ProxyConfig {
  const context = `proxies[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "hostId", "provider", "serviceId", "routes"], context);
  if (item.provider !== "nginx" && item.provider !== "caddy") {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.provider must be nginx or caddy`);
  }
  const routes = array(item.routes, `${context}.routes`).map((route, routeIndex) => {
    const routeContext = `${context}.routes[${routeIndex}]`;
    const routeObject = object(route, routeContext);
    exact(routeObject, ["hostname", "pathPrefix", "upstreamId"], routeContext);
    const hostname = string(routeObject.hostname, `${routeContext}.hostname`).toLowerCase();
    const pathPrefix = string(routeObject.pathPrefix, `${routeContext}.pathPrefix`);
    if (!/^[a-z0-9.-]+$/.test(hostname) || !pathPrefix.startsWith("/")) {
      throw new OpsHavenError("CONFIG_INVALID", `${routeContext} contains an invalid hostname or path prefix`);
    }
    return { hostname, pathPrefix, upstreamId: id(routeObject.upstreamId, `${routeContext}.upstreamId`) };
  });
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    provider: item.provider,
    serviceId: id(item.serviceId, `${context}.serviceId`),
    routes
  };
}

function parseDatabase(value: unknown, index: number): DatabaseConfig {
  const context = `databases[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "hostId", "engine", "serviceId", "evidencePath"], context);
  if (item.engine !== "postgresql" && item.engine !== "mysql" && item.engine !== "sqlite") {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.engine is unsupported`);
  }
  const serviceId = item.serviceId === undefined ? undefined : id(item.serviceId, `${context}.serviceId`);
  const evidencePath = item.evidencePath === undefined ? undefined : absolutePath(item.evidencePath, `${context}.evidencePath`);
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    engine: item.engine,
    ...(serviceId === undefined ? {} : { serviceId }),
    ...(evidencePath === undefined ? {} : { evidencePath })
  };
}

function parseMonitoring(value: unknown, index: number): MonitoringConfig {
  const context = `monitoring[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "hostId", "serviceIds"], context);
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    serviceIds: stringList(item.serviceIds, `${context}.serviceIds`, id)
  };
}

function parseBackup(value: unknown, index: number): BackupConfig {
  const context = `backups[${index}]`;
  const item = object(value, context);
  exact(item, ["id", "hostId", "provider", "evidencePath", "restoreProcedurePath", "maximumAgeSeconds"], context);
  if (item.provider !== "file-marker") throw new OpsHavenError("CONFIG_INVALID", `${context}.provider must be file-marker`);
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    provider: "file-marker",
    evidencePath: absolutePath(item.evidencePath, `${context}.evidencePath`),
    restoreProcedurePath: absolutePath(item.restoreProcedurePath, `${context}.restoreProcedurePath`),
    maximumAgeSeconds: integer(item.maximumAgeSeconds, `${context}.maximumAgeSeconds`, 60, 31_536_000)
  };
}

function parseCommandStep(value: unknown, context: string): CommandStep {
  const item = object(value, context);
  exact(item, ["executable", "args", "timeoutMs"], context);
  if (!["npm", "pnpm", "yarn", "node", "docker"].includes(String(item.executable))) {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.executable is not allowlisted`);
  }
  const executable = item.executable as CommandStep["executable"];
  const args = stringList(item.args, `${context}.args`, (entry, entryContext) => {
    const arg = string(entry, entryContext);
    if (!SAFE_STEP_ARG.test(arg) || ["-e", "--eval", "--require"].includes(arg)) {
      throw new OpsHavenError("CONFIG_INVALID", `${entryContext} is not a safe configured argument`);
    }
    return arg;
  });
  return { executable, args, timeoutMs: integer(item.timeoutMs, `${context}.timeoutMs`, 100, 1_800_000) };
}

function parseDeployment(value: unknown, index: number): DeploymentConfig {
  const context = `deployments[${index}]`;
  const item = object(value, context);
  exact(
    item,
    ["id", "hostId", "applicationId", "repositoryPath", "releasesPath", "activeSymlink", "stateFile", "allowedRefs", "strategy", "serviceIds", "probeIds", "checkSteps", "buildSteps", "migrationRisk"],
    context
  );
  if (item.strategy !== "systemd" && item.strategy !== "docker-compose") {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.strategy is unsupported`);
  }
  if (item.migrationRisk !== "none" && item.migrationRisk !== "manual-review") {
    throw new OpsHavenError("CONFIG_INVALID", `${context}.migrationRisk is unsupported`);
  }
  return {
    id: id(item.id, `${context}.id`),
    hostId: id(item.hostId, `${context}.hostId`),
    applicationId: id(item.applicationId, `${context}.applicationId`),
    repositoryPath: absolutePath(item.repositoryPath, `${context}.repositoryPath`),
    releasesPath: absolutePath(item.releasesPath, `${context}.releasesPath`),
    activeSymlink: absolutePath(item.activeSymlink, `${context}.activeSymlink`),
    stateFile: absolutePath(item.stateFile, `${context}.stateFile`),
    allowedRefs: stringList(item.allowedRefs, `${context}.allowedRefs`, (entry, entryContext) => {
      const ref = string(entry, entryContext);
      if (!SAFE_REF.test(ref) || ref.includes("..")) throw new OpsHavenError("CONFIG_INVALID", `${entryContext} is unsafe`);
      return ref;
    }),
    strategy: item.strategy,
    serviceIds: stringList(item.serviceIds, `${context}.serviceIds`, id),
    probeIds: stringList(item.probeIds, `${context}.probeIds`, id),
    checkSteps: array(item.checkSteps, `${context}.checkSteps`).map((step, stepIndex) =>
      parseCommandStep(step, `${context}.checkSteps[${stepIndex}]`)
    ),
    buildSteps: array(item.buildSteps, `${context}.buildSteps`).map((step, stepIndex) =>
      parseCommandStep(step, `${context}.buildSteps[${stepIndex}]`)
    ),
    migrationRisk: item.migrationRisk
  };
}

function parseDefaults(value: unknown): OpsHavenConfig["defaults"] {
  const item = object(value, "defaults");
  exact(item, ["timeoutMs", "output"], "defaults");
  const output = object(item.output, "defaults.output");
  exact(output, ["maxBytes", "maxLines"], "defaults.output");
  return {
    timeoutMs: integer(item.timeoutMs, "defaults.timeoutMs", 100, 120_000),
    output: {
      maxBytes: integer(output.maxBytes, "defaults.output.maxBytes", 256, 1_048_576),
      maxLines: integer(output.maxLines, "defaults.output.maxLines", 1, 10_000)
    }
  };
}

function parseSimpleObject(value: unknown, context: string, keys: readonly string[]): JsonObject {
  const item = object(value, context);
  exact(item, keys, context);
  return item;
}

function ensureReferences(config: OpsHavenConfig): void {
  const hosts = new Set(config.hosts.map((item) => item.id));
  const applications = new Map(config.applications.map((item) => [item.id, item]));
  const services = new Map(config.services.map((item) => [item.id, item]));
  const probes = new Map(config.probes.map((item) => [item.id, item]));

  const requireHost = (hostId: string, context: string): void => {
    if (!hosts.has(hostId)) throw new OpsHavenError("CONFIG_INVALID", `${context} references an unknown host`, { hostId });
  };
  for (const application of config.applications) requireHost(application.hostId, `application ${application.id}`);
  for (const service of config.services) {
    requireHost(service.hostId, `service ${service.id}`);
    const application = applications.get(service.applicationId);
    if (application?.hostId !== service.hostId) {
      throw new OpsHavenError("CONFIG_INVALID", `service ${service.id} references an invalid application`);
    }
  }
  for (const container of config.containers) {
    requireHost(container.hostId, `container ${container.id}`);
    if (applications.get(container.applicationId)?.hostId !== container.hostId) {
      throw new OpsHavenError("CONFIG_INVALID", `container ${container.id} references an invalid application`);
    }
  }
  for (const proxy of config.proxies) {
    requireHost(proxy.hostId, `proxy ${proxy.id}`);
    if (services.get(proxy.serviceId)?.hostId !== proxy.hostId) {
      throw new OpsHavenError("CONFIG_INVALID", `proxy ${proxy.id} references an invalid service`);
    }
  }
  for (const probe of config.probes) requireHost(probe.hostId, `probe ${probe.id}`);
  for (const database of config.databases) requireHost(database.hostId, `database ${database.id}`);
  for (const monitor of config.monitoring) {
    requireHost(monitor.hostId, `monitoring ${monitor.id}`);
    for (const serviceId of monitor.serviceIds) {
      if (services.get(serviceId)?.hostId !== monitor.hostId) {
        throw new OpsHavenError("CONFIG_INVALID", `monitoring ${monitor.id} references an invalid service`);
      }
    }
  }
  for (const backup of config.backups) requireHost(backup.hostId, `backup ${backup.id}`);
  for (const deployment of config.deployments) {
    requireHost(deployment.hostId, `deployment ${deployment.id}`);
    if (applications.get(deployment.applicationId)?.hostId !== deployment.hostId) {
      throw new OpsHavenError("CONFIG_INVALID", `deployment ${deployment.id} references an invalid application`);
    }
    for (const serviceId of deployment.serviceIds) {
      if (services.get(serviceId)?.hostId !== deployment.hostId) {
        throw new OpsHavenError("CONFIG_INVALID", `deployment ${deployment.id} references an invalid service`);
      }
    }
    for (const probeId of deployment.probeIds) {
      if (probes.get(probeId)?.hostId !== deployment.hostId) {
        throw new OpsHavenError("CONFIG_INVALID", `deployment ${deployment.id} references an invalid probe`);
      }
    }
  }
}

export function parseConfig(value: unknown): OpsHavenConfig {
  const root = object(value, "config");
  exact(root, ["version", "policyVersion", "defaults", "audit", "approvals", "secrets", "hosts", "applications", "services", "containers", "deployments", "proxies", "probes", "databases", "monitoring", "backups"], "config");
  if (root.version !== 1) throw new OpsHavenError("CONFIG_INVALID", "config.version must be 1");

  const audit = parseSimpleObject(root.audit, "audit", ["path"]);
  const approvals = parseSimpleObject(root.approvals, "approvals", ["stateDirectory", "ttlSeconds", "keyEnvironmentVariable"]);
  const secrets = parseSimpleObject(root.secrets, "secrets", ["fingerprints", "keyNames"]);

  const config: OpsHavenConfig = {
    version: 1,
    policyVersion: string(root.policyVersion, "policyVersion"),
    defaults: parseDefaults(root.defaults),
    audit: { path: absolutePath(audit.path, "audit.path") },
    approvals: {
      stateDirectory: absolutePath(approvals.stateDirectory, "approvals.stateDirectory"),
      ttlSeconds: integer(approvals.ttlSeconds, "approvals.ttlSeconds", 30, 3600),
      keyEnvironmentVariable: string(approvals.keyEnvironmentVariable, "approvals.keyEnvironmentVariable")
    },
    secrets: {
      fingerprints: stringList(secrets.fingerprints, "secrets.fingerprints", string),
      keyNames: stringList(secrets.keyNames, "secrets.keyNames", string)
    },
    hosts: array(root.hosts, "hosts").map(parseHost),
    applications: array(root.applications, "applications").map(parseApplication),
    services: array(root.services, "services").map(parseService),
    containers: array(root.containers, "containers").map(parseContainer),
    deployments: array(root.deployments, "deployments").map(parseDeployment),
    proxies: array(root.proxies, "proxies").map(parseProxy),
    probes: array(root.probes, "probes").map(parseProbe),
    databases: array(root.databases, "databases").map(parseDatabase),
    monitoring: array(root.monitoring, "monitoring").map(parseMonitoring),
    backups: array(root.backups, "backups").map(parseBackup)
  };

  uniqueIds(config.hosts, "hosts");
  uniqueIds(config.applications, "applications");
  uniqueIds(config.services, "services");
  uniqueIds(config.containers, "containers");
  uniqueIds(config.deployments, "deployments");
  uniqueIds(config.proxies, "proxies");
  uniqueIds(config.probes, "probes");
  uniqueIds(config.databases, "databases");
  uniqueIds(config.monitoring, "monitoring");
  uniqueIds(config.backups, "backups");

  ensureReferences(config);
  return config;
}
