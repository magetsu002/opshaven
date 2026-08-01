import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { AuditLog, type AuditEvent } from "../audit.js";
import { sha256 } from "../canonical.js";
import { loadConfig, parseConfig, type OpsHavenConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { OperationService } from "../operations.js";
import {
  DEPLOYMENT_BUILD_STRATEGY,
  DEPLOYMENT_MINIMUM_DISK_BYTES,
  DEPLOYMENT_PLAN_TTL_MS,
  DEPLOYMENT_ROLLBACK_BEHAVIOR,
  DeploymentPlanStore,
  DeploymentRegistry,
  applicationBinding,
  applicationFromConfig,
  availableDiskBytes,
  configDocument,
  dataOf,
  deploymentOperations,
  generatedResources,
  nextDeploymentPolicyVersion,
  observedFingerprint,
  operationDefinitionsDigest,
  operatorProfileDigest,
  readProtectedDocument,
  replaceProtectedDocument,
  rollbackOperations,
  selectDeploymentHost,
  targetIdentityDigest,
  validateApplicationId,
  validateApplicationName,
  validateExactRevision,
  validateHealthUrl,
  validateServiceIdentifier,
  type ApplicationRegistrationInput,
  type DeploymentApplication,
  type DeploymentPlan,
  type ObservedDeploymentState,
  type OperationClient,
  type StoredDeploymentPlan,
} from "./model.js";

export interface DeploymentPlannerOptions {
  root?: string;
  client?: OperationClient;
  now?: () => number;
  nonce?: () => string;
}

export interface DeploymentRevisionChoice {
  revision: string;
  label: string;
  recommended: boolean;
}

interface AuditFields {
  operation: string;
  applicationId: string;
  planId?: string;
  sourceRevision?: string;
  targetRevision?: string;
  targetIdentity?: string;
  authorizationIdentity?: string;
  operationResult: "success" | "denied" | "failure";
  mutation: boolean;
  finalOutcome?: string;
  evidence?: unknown;
}

export async function deploymentAudit(config: OpsHavenConfig, fields: AuditFields): Promise<void> {
  const event = {
    timestamp: new Date().toISOString(),
    requestId: randomBytes(12).toString("hex"),
    actor: "operator-cli",
    operation: fields.operation,
    resourceId: fields.applicationId,
    mutation: fields.mutation,
    dryRun: !fields.mutation,
    outcome: fields.operationResult === "denied" ? "denied" : fields.operationResult,
    ...(fields.planId ? { planId: fields.planId, approvalDigest: fields.planId.replace("sha256:", "") } : {}),
    ...(fields.sourceRevision ? { sourceRevision: fields.sourceRevision } : {}),
    ...(fields.targetRevision ? { targetRevision: fields.targetRevision } : {}),
    ...(fields.targetIdentity ? { targetIdentity: fields.targetIdentity } : {}),
    ...(fields.authorizationIdentity ? { authorizationIdentity: fields.authorizationIdentity } : {}),
    operationResult: fields.operationResult,
    ...(fields.finalOutcome ? { finalOutcome: fields.finalOutcome } : {}),
    ...(fields.evidence === undefined ? {} : { evidenceDigest: sha256(fields.evidence), redactedEvidence: fields.evidence }),
  } as unknown as AuditEvent;
  await new AuditLog(config.audit.path).append(event);
}

export async function requireHealthyDeploymentAudit(config: OpsHavenConfig): Promise<void> {
  const verification = await new AuditLog(config.audit.path).verify();
  if (!verification.valid) throw new OpsHavenError("AUDIT_FAILED", "Existing audit chain failed verification.");
}

function stringValue(value: unknown): string { return typeof value === "string" ? value : ""; }
function numberValue(value: unknown): number { return typeof value === "number" && Number.isFinite(value) ? value : 0; }
function booleanValue(value: unknown): boolean { return value === true; }

function remoteSetupRequired(error: unknown): boolean {
  const message = error instanceof Error ? error.message : "";
  return /unknown resource|operator capability|policy version|authorization|remote configuration|incompatible remote resource/i.test(message);
}

export class DeploymentPlanner {
  readonly registry: DeploymentRegistry;
  readonly plans: DeploymentPlanStore;
  readonly client: OperationClient;
  readonly now: () => number;
  readonly nonce: () => string;

  constructor(readonly config: OpsHavenConfig, readonly configPath: string, options: DeploymentPlannerOptions = {}) {
    this.registry = new DeploymentRegistry(options.root);
    this.plans = new DeploymentPlanStore(options.root);
    this.client = options.client ?? new OperationService(config, undefined, configPath);
    this.now = options.now ?? (() => Date.now());
    this.nonce = options.nonce ?? (() => randomBytes(16).toString("hex"));
  }

  static async load(configPath: string, options: DeploymentPlannerOptions = {}): Promise<DeploymentPlanner> {
    return new DeploymentPlanner(await loadConfig(configPath), configPath, options);
  }

  async registerApplication(input: ApplicationRegistrationInput): Promise<DeploymentApplication> {
    if ((input.buildStrategy ?? DEPLOYMENT_BUILD_STRATEGY) !== DEPLOYMENT_BUILD_STRATEGY) throw new OpsHavenError("CONFIG_INVALID", "Only the fixed Git, npm build, systemd, and HTTP health profile is supported.");
    if ((input.rollbackBehavior ?? DEPLOYMENT_ROLLBACK_BEHAVIOR) !== DEPLOYMENT_ROLLBACK_BEHAVIOR) throw new OpsHavenError("CONFIG_INVALID", "Automatic restoration of the previous active release is required.");
    validateApplicationId(input.id);
    validateApplicationName(input.name);
    validateServiceIdentifier(input.serviceIdentifier);
    validateHealthUrl(input.healthCheckUrl);
    const host = selectDeploymentHost(this.config, input.remoteTarget);
    await requireHealthyDeploymentAudit(this.config);

    const localDocument = await readProtectedDocument(this.configPath, "Local operator configuration");
    const dispatcherPath = `${this.configPath}.dispatcher.json`;
    const remoteDocument = await readProtectedDocument(dispatcherPath, "Remote deployment configuration");
    let localRaw: unknown;
    let remoteRaw: unknown;
    try { localRaw = JSON.parse(localDocument.text) as unknown; remoteRaw = JSON.parse(remoteDocument.text) as unknown; }
    catch { throw new OpsHavenError("CONFIG_INVALID", "Protected configuration JSON is invalid."); }
    const local = configDocument(localRaw);
    const remote = configDocument(remoteRaw);
    const resources = generatedResources(input, host.id);
    const generatedIds = new Set(resources.map((item) => String(item.id)));
    for (const document of [local, remote]) {
      const existing = document.resources as unknown[];
      if (existing.some((item) => item && typeof item === "object" && !Array.isArray(item) && generatedIds.has(String((item as Record<string, unknown>).id)))) {
        throw new OpsHavenError("POLICY_DENIED", "Application ID is already registered. No changes were made.");
      }
      const hostExists = existing.some((item) => item && typeof item === "object" && !Array.isArray(item) && (item as Record<string, unknown>).id === host.id && (item as Record<string, unknown>).kind === "host");
      if (!hostExists) throw new OpsHavenError("CONFIG_INVALID", "Configured remote target is missing from the deployment policy.");
      document.resources = [...existing, ...resources];
    }
    const policyVersion = nextDeploymentPolicyVersion(String(local.policyVersion), local.resources as unknown[]);
    local.policyVersion = policyVersion;
    remote.policyVersion = policyVersion;
    const nextLocal = parseConfig(local);
    parseConfig(remote);
    const app = applicationFromConfig(nextLocal, input, host, new Date(this.now()).toISOString());
    let localChanged = false;
    let remoteChanged = false;
    let appChanged = false;
    try {
      await replaceProtectedDocument(this.configPath, localDocument, `${JSON.stringify(local, null, 2)}\n`);
      localChanged = true;
      await replaceProtectedDocument(dispatcherPath, remoteDocument, `${JSON.stringify(remote, null, 2)}\n`);
      remoteChanged = true;
      await this.registry.create(app);
      appChanged = true;
      await deploymentAudit(nextLocal, {
        operation: "deployment_application_registration",
        applicationId: app.id,
        targetIdentity: await targetIdentityDigest(host),
        authorizationIdentity: await operatorProfileDigest(nextLocal),
        operationResult: "success",
        mutation: true,
        evidence: { applicationId: app.id, bindingDigest: app.resourceBindingDigest, policyVersion },
      });
      return app;
    } catch (error) {
      if (appChanged) await this.registry.remove(app.id).catch(() => undefined);
      if (remoteChanged) {
        const current = await readProtectedDocument(dispatcherPath, "Remote deployment configuration").catch(() => null);
        if (current) await replaceProtectedDocument(dispatcherPath, current, remoteDocument.text).catch(() => undefined);
      }
      if (localChanged) {
        const current = await readProtectedDocument(this.configPath, "Local operator configuration").catch(() => null);
        if (current) await replaceProtectedDocument(this.configPath, current, localDocument.text).catch(() => undefined);
      }
      throw error;
    }
  }

  async inspect(app: DeploymentApplication, revision?: string): Promise<ObservedDeploymentState> {
    const binding = applicationBinding(this.config, app);
    const actor = `deployment-plan:${app.id}`;
    const deployed = dataOf(await this.client.execute("get_deployed_commit", { resourceId: app.deploymentResourceId }, undefined, actor), "Current release inspection");
    const service = dataOf(await this.client.execute("get_service_status", { resourceId: app.serviceResourceId }, undefined, actor), "Service inspection");
    const health = dataOf(await this.client.execute("run_health_probe", { resourceId: app.probeResourceId }, undefined, actor), "Health inspection");
    const host = dataOf(await this.client.execute("get_host_summary", { resourceId: app.hostResourceId }, undefined, actor), "Host inspection");
    let verified = true;
    if (revision) {
      const dryRun = dataOf(await this.client.execute("deploy_commit", { resourceId: app.deploymentResourceId, commit: revision, dryRun: true }, undefined, actor), "Revision verification");
      const plan = dryRun.plan && typeof dryRun.plan === "object" && !Array.isArray(dryRun.plan) ? dryRun.plan as Record<string, unknown> : {};
      verified = stringValue(plan.commit).toLowerCase() === revision.toLowerCase();
    }
    const currentRevision = stringValue(deployed.activeCommit).toLowerCase();
    const activeReleaseId = stringValue(deployed.activeReleaseId);
    const observed: ObservedDeploymentState = {
      currentRevision,
      activeReleaseId,
      sourceRepositoryRevision: stringValue(deployed.sourceRepositoryCommit).toLowerCase(),
      sourceRepositoryDirty: booleanValue(deployed.dirty),
      serviceIdentifier: stringValue(service.unit),
      serviceActiveState: stringValue(service.activeState),
      serviceSubState: stringValue(service.subState),
      serviceExitStatus: numberValue(service.exitStatus),
      healthReachable: booleanValue(health.reachable),
      healthExpected: booleanValue(health.expected),
      healthStatusCode: numberValue(health.statusCode),
      availableDiskBytes: availableDiskBytes(host.rootFilesystem),
      runtimeAvailable: stringValue(host.uname).length > 0,
      rollbackAvailable: /^[a-f0-9]{40}$/i.test(currentRevision) && activeReleaseId.length > 0,
      targetRevisionVerified: verified,
    };
    if (binding.service.unit !== observed.serviceIdentifier) throw new OpsHavenError("POLICY_DENIED", "Approved service identity did not match remote observation.");
    return observed;
  }

  async discoverRevisions(applicationId: string): Promise<DeploymentRevisionChoice[]> {
    const app = await this.registry.get(applicationId);
    const observed = await this.inspect(app);
    if (observed.sourceRepositoryDirty) {
      throw new OpsHavenError("POLICY_DENIED", "The configured application repository has uncommitted changes and cannot provide a reviewed revision.");
    }

    let revision: string;
    try {
      revision = validateExactRevision(observed.sourceRepositoryRevision);
    } catch {
      throw new OpsHavenError("POLICY_DENIED", "The configured application repository did not provide a complete Git commit SHA.");
    }

    if (revision === observed.currentRevision) {
      throw new OpsHavenError("POLICY_DENIED", "No different verified application revision is currently available for deployment.");
    }

    const verified = await this.inspect(app, revision);
    if (!verified.targetRevisionVerified) {
      throw new OpsHavenError("POLICY_DENIED", "The discovered revision was not verified in the configured repository source.");
    }

    return [{
      revision,
      label: app.id === "sample-api"
        ? "Recommended healthy sample revision"
        : "Verified repository revision",
      recommended: true,
    }];
  }

  private async planInputs(app: DeploymentApplication, revision: string): Promise<{ observed: ObservedDeploymentState; identity: string; profile: string; definitions: string }> {
    const binding = applicationBinding(this.config, app);
    const [observed, identity, profile] = await Promise.all([this.inspect(app, revision), targetIdentityDigest(binding.host), operatorProfileDigest(this.config)]);
    const definitions = operationDefinitionsDigest(this.config, app);
    if (observed.sourceRepositoryDirty) throw new OpsHavenError("POLICY_DENIED", "Deployment source repository is dirty. No changes were made.");
    if (!observed.targetRevisionVerified) throw new OpsHavenError("POLICY_DENIED", "Requested revision was not verified in the configured repository source.");
    if (!observed.rollbackAvailable) throw new OpsHavenError("POLICY_DENIED", "A verified previous active release is required for automatic rollback.");
    if (observed.availableDiskBytes < DEPLOYMENT_MINIMUM_DISK_BYTES) throw new OpsHavenError("POLICY_DENIED", "Available disk space is below the supported deployment minimum.");
    if (!observed.runtimeAvailable) throw new OpsHavenError("POLICY_DENIED", "Required remote runtime is unavailable.");
    if (observed.serviceActiveState !== "active" || !observed.healthReachable || !observed.healthExpected) throw new OpsHavenError("POLICY_DENIED", "The current release must be active and healthy before planning.");
    if (observed.currentRevision === revision) throw new OpsHavenError("POLICY_DENIED", "Target revision is already active. No changes were made.");
    return { observed, identity, profile, definitions };
  }

  async createPlan(applicationId: string, revisionInput: string): Promise<StoredDeploymentPlan> {
    const app = await this.registry.get(applicationId);
    const revision = validateExactRevision(revisionInput);
    await requireHealthyDeploymentAudit(this.config);
    try {
      const inputs = await this.planInputs(app, revision);
      const stateFingerprint = observedFingerprint(inputs.observed);
      const deterministicKey = sha256({ application: app.resourceBindingDigest, revision, stateFingerprint, policyVersion: this.config.policyVersion, identity: inputs.identity, profile: inputs.profile, definitions: inputs.definitions });
      const reusable = await this.plans.reusable(deterministicKey, this.now());
      if (reusable) return reusable;
      const operations = deploymentOperations(this.config, app, revision);
      const plan: DeploymentPlan = {
        schemaVersion: 1,
        applicationId: app.id,
        target: { label: app.targetLabel, hostResourceId: app.hostResourceId, identityDigest: inputs.identity },
        observedStateFingerprint: stateFingerprint,
        observed: inputs.observed,
        currentRevision: inputs.observed.currentRevision,
        targetRevision: revision,
        operations,
        requiredAuthorization: {
          mechanism: "opshaven-exact-operation-approval-v1",
          operatorProfileDigest: inputs.profile,
          scopeDigest: sha256({ applicationId: app.id, resourceId: app.deploymentResourceId, currentRevision: inputs.observed.currentRevision, targetRevision: revision, operations }),
        },
        requiredPrivileges: ["restricted remote deployment account", `restart ${app.serviceIdentifier}`],
        healthChecks: [{ probeResourceId: app.probeResourceId, endpointDigest: sha256(app.healthCheckUrl), expectedStatus: app.expectedStatus, timeoutMs: applicationBinding(this.config, app).probe.timeoutMs, exactRevisionEvidence: true }],
        rollback: { strategy: "restore-previous-active-release", available: true, releaseId: inputs.observed.activeReleaseId, revision: inputs.observed.currentRevision, operations: rollbackOperations(this.config, app, revision) },
        risk: { classification: "controlled-application-release", mutatesReleaseState: true, restartsApprovedServices: [app.serviceIdentifier], migrations: "unsupported" },
        policyVersion: this.config.policyVersion,
        applicationConfigDigest: app.resourceBindingDigest,
        operationDefinitionsDigest: inputs.definitions,
        createdAt: new Date(this.now()).toISOString(),
        expiresAt: new Date(this.now() + DEPLOYMENT_PLAN_TTL_MS).toISOString(),
        nonce: this.nonce(),
      };
      if (!/^[a-f0-9]{32}$/.test(plan.nonce)) throw new OpsHavenError("INTERNAL_ERROR", "Plan nonce generation failed safely.");
      const stored = await this.plans.save(plan);
      try {
        await this.plans.index(deterministicKey, stored.planId);
        await deploymentAudit(this.config, {
          operation: "deployment_plan_creation", applicationId: app.id, planId: stored.planId, sourceRevision: plan.currentRevision, targetRevision: plan.targetRevision,
          targetIdentity: plan.target.identityDigest, authorizationIdentity: plan.requiredAuthorization.operatorProfileDigest, operationResult: "success", mutation: false,
          evidence: { observedStateFingerprint: plan.observedStateFingerprint, expiresAt: plan.expiresAt, operationDefinitionsDigest: plan.operationDefinitionsDigest },
        });
      } catch (error) {
        await fs.rm(`${this.plans.root}/plans/${stored.planId.replace("sha256:", "")}.json`, { force: true });
        throw error;
      }
      return stored;
    } catch (error) {
      await deploymentAudit(this.config, {
        operation: "deployment_plan_rejection", applicationId: app.id, targetRevision: revision, operationResult: "denied", mutation: false,
        evidence: { errorCode: error instanceof OpsHavenError ? error.code : "INTERNAL_ERROR", messageDigest: sha256(error instanceof Error ? error.message : "planning failed safely") },
      }).catch((auditError: unknown) => { throw auditError; });
      throw error;
    }
  }

  async revalidate(stored: StoredDeploymentPlan, app: DeploymentApplication): Promise<ObservedDeploymentState> {
    const plan = stored.plan;
    if (Date.parse(plan.expiresAt) <= this.now()) throw new OpsHavenError("APPROVAL_EXPIRED", "Deployment plan expired. No changes were made. Create a new deployment plan.");
    const binding = applicationBinding(this.config, app);
    const [identity, profile, observed] = await Promise.all([targetIdentityDigest(binding.host), operatorProfileDigest(this.config), this.inspect(app, plan.targetRevision)]);
    if (plan.applicationId !== app.id || plan.applicationConfigDigest !== app.resourceBindingDigest || plan.policyVersion !== this.config.policyVersion
      || plan.operationDefinitionsDigest !== operationDefinitionsDigest(this.config, app) || plan.target.identityDigest !== identity
      || plan.requiredAuthorization.operatorProfileDigest !== profile || plan.currentRevision !== observed.currentRevision
      || plan.observedStateFingerprint !== observedFingerprint(observed) || !observed.rollbackAvailable || observed.activeReleaseId !== plan.rollback.releaseId) {
      throw new OpsHavenError("POLICY_DENIED", "Deployment plan is stale. The remote deployment state or authorization changed after planning. No changes were made. Create a new deployment plan.");
    }
    return observed;
  }

  async deploymentDoctor(): Promise<{ apps: DeploymentApplication[]; checks: { label: string; passed: boolean; detail?: string }[]; next: string }> {
    const apps = await this.registry.list();
    if (apps.length === 0) {
      return {
        apps,
        checks: [{ label: "No application registered", passed: false, detail: "Register one supported deployment application" }],
        next: "opshaven app add",
      };
    }

    const checks: { label: string; passed: boolean; detail?: string }[] = [];
    let next = `opshaven deploy plan ${apps[0]?.id ?? "sample-api"}`;

    for (const app of apps) {
      try {
        applicationBinding(this.config, app);
        checks.push({ label: `${app.name} registered`, passed: true });
        const observed = await this.inspect(app);
        const repositoryAvailable = /^[a-f0-9]{40}$/i.test(observed.sourceRepositoryRevision) && !observed.sourceRepositoryDirty;
        checks.push({
          label: `${app.name}: repository available`,
          passed: repositoryAvailable,
          ...(repositoryAvailable ? {} : { detail: "The configured remote Git repository did not provide a clean complete revision" }),
        });

        let verifiedRevision = false;
        if (repositoryAvailable && observed.sourceRepositoryRevision !== observed.currentRevision) {
          const verified = await this.inspect(app, observed.sourceRepositoryRevision);
          verifiedRevision = verified.targetRevisionVerified;
        }
        checks.push({
          label: `${app.name}: verified revision available`,
          passed: verifiedRevision,
          ...(verifiedRevision ? {} : { detail: "No different verified immutable revision is ready for planning" }),
        });
        checks.push({ label: `${app.name}: remote release layout ready`, passed: observed.rollbackAvailable });
        checks.push({ label: `${app.name}: approved service available`, passed: observed.serviceActiveState === "active" });
        checks.push({ label: `${app.name}: health check reachable`, passed: observed.healthReachable && observed.healthExpected });
        checks.push({ label: `${app.name}: rollback location available`, passed: observed.rollbackAvailable });
      } catch (error) {
        checks.push({
          label: `${app.name}: deployment readiness`,
          passed: false,
          detail: error instanceof Error ? error.message : "verification failed safely",
        });
        if (remoteSetupRequired(error)) next = "opshaven setup remote";
        else next = "opshaven doctor --debug";
      }
    }

    return { apps, checks, next };
  }
}
