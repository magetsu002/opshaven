import { promises as fs } from "node:fs";
import path from "node:path";
import { OpsHavenError } from "../errors.js";

export type SetupScope = "local" | "remote";
export type SetupMutationAction = "create" | "replace" | "remove" | "verify";
export type SetupStepState = "pending" | "passed" | "failed" | "skipped" | "rolled-back";

export interface SetupMutation {
  readonly id: string;
  readonly scope: SetupScope;
  readonly action: SetupMutationAction;
  readonly path: string;
  readonly mode?: string;
  readonly owner?: string;
  readonly reason: string;
  readonly destructive: boolean;
}

export interface SetupCheck {
  readonly id: string;
  readonly state: SetupStepState;
  readonly detail: string;
}

export interface SetupRollbackState {
  readonly required: boolean;
  readonly attempted: boolean;
  readonly completed: boolean;
  readonly restored: readonly string[];
}

export interface SetupReceipt {
  readonly version: 1;
  readonly receiptId: string;
  readonly sourceSha: string;
  readonly target: string;
  readonly dryRun: boolean;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly certified: boolean;
  readonly mutations: readonly SetupMutation[];
  readonly checks: readonly SetupCheck[];
  readonly rollback: SetupRollbackState;
}

export interface RemoteSetupConfig {
  readonly version: 1;
  readonly policyConfigPath: string;
  readonly expectedSourceSha: string;
  readonly target: {
    readonly host: string;
    readonly port: number;
    readonly adminUser: string;
    readonly knownHostsFile: string;
    readonly identityFile: string;
    readonly expectedHostKeySha256: string;
    readonly privilege: "root" | "sudo-noninteractive";
  };
  readonly local: {
    readonly runtimeRoot: string;
    readonly dispatcherPath: string;
    readonly wrapperTemplatePath: string;
    readonly capabilityDeclarationPath: string;
    readonly operatorPrivateKeyFile: string;
    readonly operatorPublicKeyFile: string;
    readonly restrictedAuthorizedKeyFile: string;
  };
  readonly remote: {
    readonly account: "opshaven";
    readonly runtimeRoot: "/usr/lib/opshaven";
    readonly configPath: "/etc/opshaven/config.json";
    readonly wrapperPath: "/usr/local/bin/opshaven-readonly-force-command";
    readonly stateDirectory: "/var/lib/opshaven";
    readonly receiptPath: "/var/lib/opshaven/setup-receipt.json";
    readonly nodeCandidates: readonly string[];
  };
  readonly trust: { readonly expiresInSeconds: number };
}

export interface RemoteSetupPlan {
  readonly version: 1;
  readonly sourceSha: string;
  readonly target: string;
  readonly mutations: readonly SetupMutation[];
}

export interface RemoteSetupRunOptions {
  readonly dryRun: boolean;
  readonly nonInteractive: boolean;
  readonly tui: boolean;
}

const SHA = /^[a-f0-9]{40}$/;
const HOST = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|[0-9A-Fa-f:]+)$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{20,60}$/;
const ABSOLUTE = /^\/[A-Za-z0-9._/@+-]+(?:\/[A-Za-z0-9._@+-]+)*$/;

function plain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function exact(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  if (Object.keys(value).some((key) => !allowed.has(key)) || keys.some((key) => !(key in value))) {
    throw new OpsHavenError("CONFIG_INVALID", `${label} has an incompatible schema.`);
  }
}

function text(value: unknown, label: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new OpsHavenError("CONFIG_INVALID", `${label} is invalid.`);
  return value;
}

function integer(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new OpsHavenError("CONFIG_INVALID", `${label} is outside its reviewed bounds.`);
  }
  return value as number;
}

function absolute(value: unknown, label: string): string {
  const result = text(value, label, ABSOLUTE);
  if (path.normalize(result) !== result || result.includes("..")) throw new OpsHavenError("CONFIG_INVALID", `${label} must be a normalized absolute path.`);
  return result;
}

function fixed(value: unknown, expected: string, label: string): string {
  if (value !== expected) throw new OpsHavenError("CONFIG_INVALID", `${label} must be ${expected}.`);
  return expected;
}

export function parseRemoteSetupConfig(value: unknown): RemoteSetupConfig {
  if (!plain(value)) throw new OpsHavenError("CONFIG_INVALID", "Remote setup configuration is malformed.");
  exact(value, ["version", "policyConfigPath", "expectedSourceSha", "target", "local", "remote", "trust"], "Remote setup configuration");
  if (value.version !== 1) throw new OpsHavenError("CONFIG_INVALID", "Only remote setup configuration version 1 is supported.");
  if (!plain(value.target) || !plain(value.local) || !plain(value.remote) || !plain(value.trust)) throw new OpsHavenError("CONFIG_INVALID", "Remote setup configuration sections are malformed.");
  exact(value.target, ["host", "port", "adminUser", "knownHostsFile", "identityFile", "expectedHostKeySha256", "privilege"], "Remote setup target");
  exact(value.local, ["runtimeRoot", "dispatcherPath", "wrapperTemplatePath", "capabilityDeclarationPath", "operatorPrivateKeyFile", "operatorPublicKeyFile", "restrictedAuthorizedKeyFile"], "Remote setup local paths");
  exact(value.remote, ["account", "runtimeRoot", "configPath", "wrapperPath", "stateDirectory", "receiptPath", "nodeCandidates"], "Remote setup remote paths");
  exact(value.trust, ["expiresInSeconds"], "Remote setup trust policy");
  if (value.target.privilege !== "root" && value.target.privilege !== "sudo-noninteractive") throw new OpsHavenError("CONFIG_INVALID", "Remote setup privilege mode is invalid.");
  if (!Array.isArray(value.remote.nodeCandidates) || value.remote.nodeCandidates.length === 0 || value.remote.nodeCandidates.length > 8) throw new OpsHavenError("CONFIG_INVALID", "Remote setup node candidates must be a bounded non-empty array.");
  const nodeCandidates = value.remote.nodeCandidates.map((candidate, index) => absolute(candidate, `remote.nodeCandidates[${index}]`));
  if (new Set(nodeCandidates).size !== nodeCandidates.length) throw new OpsHavenError("CONFIG_INVALID", "Remote setup node candidates contain duplicates.");
  return Object.freeze({
    version: 1,
    policyConfigPath: absolute(value.policyConfigPath, "policyConfigPath"),
    expectedSourceSha: text(value.expectedSourceSha, "expectedSourceSha", SHA),
    target: Object.freeze({
      host: text(value.target.host, "target.host", HOST),
      port: integer(value.target.port, "target.port", 1, 65535),
      adminUser: text(value.target.adminUser, "target.adminUser", USER),
      knownHostsFile: absolute(value.target.knownHostsFile, "target.knownHostsFile"),
      identityFile: absolute(value.target.identityFile, "target.identityFile"),
      expectedHostKeySha256: text(value.target.expectedHostKeySha256, "target.expectedHostKeySha256", FINGERPRINT),
      privilege: value.target.privilege,
    }),
    local: Object.freeze({
      runtimeRoot: absolute(value.local.runtimeRoot, "local.runtimeRoot"),
      dispatcherPath: absolute(value.local.dispatcherPath, "local.dispatcherPath"),
      wrapperTemplatePath: absolute(value.local.wrapperTemplatePath, "local.wrapperTemplatePath"),
      capabilityDeclarationPath: absolute(value.local.capabilityDeclarationPath, "local.capabilityDeclarationPath"),
      operatorPrivateKeyFile: absolute(value.local.operatorPrivateKeyFile, "local.operatorPrivateKeyFile"),
      operatorPublicKeyFile: absolute(value.local.operatorPublicKeyFile, "local.operatorPublicKeyFile"),
      restrictedAuthorizedKeyFile: absolute(value.local.restrictedAuthorizedKeyFile, "local.restrictedAuthorizedKeyFile"),
    }),
    remote: Object.freeze({
      account: fixed(value.remote.account, "opshaven", "remote.account") as "opshaven",
      runtimeRoot: fixed(value.remote.runtimeRoot, "/usr/lib/opshaven", "remote.runtimeRoot") as "/usr/lib/opshaven",
      configPath: fixed(value.remote.configPath, "/etc/opshaven/config.json", "remote.configPath") as "/etc/opshaven/config.json",
      wrapperPath: fixed(value.remote.wrapperPath, "/usr/local/bin/opshaven-readonly-force-command", "remote.wrapperPath") as "/usr/local/bin/opshaven-readonly-force-command",
      stateDirectory: fixed(value.remote.stateDirectory, "/var/lib/opshaven", "remote.stateDirectory") as "/var/lib/opshaven",
      receiptPath: fixed(value.remote.receiptPath, "/var/lib/opshaven/setup-receipt.json", "remote.receiptPath") as "/var/lib/opshaven/setup-receipt.json",
      nodeCandidates: Object.freeze(nodeCandidates),
    }),
    trust: Object.freeze({ expiresInSeconds: integer(value.trust.expiresInSeconds, "trust.expiresInSeconds", 300, 31536000) }),
  });
}

export async function loadRemoteSetupConfig(filePath: string): Promise<RemoteSetupConfig> {
  let parsed: unknown;
  try { parsed = JSON.parse(await fs.readFile(filePath, "utf8")) as unknown; }
  catch { throw new OpsHavenError("CONFIG_INVALID", "Remote setup configuration could not be read as JSON."); }
  return parseRemoteSetupConfig(parsed);
}

function mutation(id: string, scope: SetupScope, action: SetupMutationAction, filePath: string, reason: string, options: { mode?: string; owner?: string; destructive?: boolean } = {}): SetupMutation {
  return Object.freeze({ id, scope, action, path: filePath, reason, destructive: options.destructive ?? false, ...(options.mode === undefined ? {} : { mode: options.mode }), ...(options.owner === undefined ? {} : { owner: options.owner }) });
}

export function buildRemoteSetupPlan(config: RemoteSetupConfig): RemoteSetupPlan {
  const remote = config.remote;
  const mutations: SetupMutation[] = [
    mutation("account", "remote", "create", remote.account, "Create the locked restricted service account.", { owner: "root" }),
    mutation("state", "remote", "create", remote.stateDirectory, "Create private replay and setup state.", { mode: "0700", owner: "opshaven:opshaven" }),
    mutation("runtime", "remote", "replace", remote.runtimeRoot, "Atomically install the complete compiled read-only runtime tree.", { mode: "0755", owner: "root:root", destructive: true }),
    mutation("wrapper", "remote", "replace", remote.wrapperPath, "Install the fixed forced-command wrapper with the resolved Node executable.", { mode: "0755", owner: "root:root", destructive: true }),
    mutation("config", "remote", "replace", remote.configPath, "Install the trusted read-only dispatcher configuration.", { mode: "0644", owner: "root:root", destructive: true }),
    mutation("authorized-key", "remote", "replace", `/home/${remote.account}/.ssh/authorized_keys`, "Install one forced-command-only restricted SSH key.", { mode: "0600", owner: "opshaven:opshaven", destructive: true }),
    mutation("operator-public-key", "remote", "replace", "/etc/opshaven/approval-public.pem", "Install only the operator verification public key.", { mode: "0644", owner: "root:root", destructive: true }),
    mutation("capability", "remote", "replace", `${remote.configPath}.capability.json`, "Install the signed read-only capability bound to the dispatcher hash.", { mode: "0600", owner: "root:root", destructive: true }),
    mutation("declaration", "remote", "replace", `${remote.configPath}.declaration.json`, "Install the reviewed capability declaration.", { mode: "0644", owner: "root:root", destructive: true }),
    mutation("declaration-binding", "remote", "replace", `${remote.configPath}.declaration-binding.json`, "Install the signed declaration binding.", { mode: "0600", owner: "root:root", destructive: true }),
    mutation("response-key", "remote", "create", `${remote.configPath}.response-private.pem`, "Generate a remote-only response signing key.", { mode: "0600", owner: "root:root" }),
    mutation("receipt", "remote", "replace", remote.receiptPath, "Write the final installation and certification receipt.", { mode: "0600", owner: "root:root", destructive: true }),
    mutation("boundary", "local", "verify", config.policyConfigPath, "Block endpoint handoff until the installed boundary is certified."),
  ];
  return Object.freeze({ version: 1, sourceSha: config.expectedSourceSha, target: `${config.target.adminUser}@${config.target.host}:${config.target.port}`, mutations: Object.freeze(mutations) });
}

export function formatRemoteSetupPlan(plan: RemoteSetupPlan): string {
  const lines = [`Remote setup plan for ${plan.target}`, `Source ${plan.sourceSha}`];
  for (const item of plan.mutations) lines.push(`${item.scope === "local" ? "LOCAL" : "VPS  "} ${item.action.toUpperCase().padEnd(7)} ${item.path} — ${item.reason}`);
  lines.push("No mutations were performed.");
  return `${lines.join("\n")}\n`;
}

function value(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}

export async function runRemoteSetupCommand(args: readonly string[]): Promise<void> {
  const configPath = value(args, "--config");
  if (!configPath) throw new OpsHavenError("CONFIG_INVALID", "Remote setup requires --config with an absolute setup configuration path.");
  const config = await loadRemoteSetupConfig(configPath);
  const options: RemoteSetupRunOptions = Object.freeze({ dryRun: args.includes("--dry-run"), nonInteractive: args.includes("--non-interactive"), tui: args.includes("--tui") });
  const plan = buildRemoteSetupPlan(config);
  if (options.dryRun) {
    process.stdout.write(args.includes("--json") ? `${JSON.stringify(plan)}\n` : formatRemoteSetupPlan(plan));
    return;
  }
  throw new OpsHavenError("POLICY_DENIED", "Remote setup is blocked until preflight verification and the transactional installer are available. Run with --dry-run to review the exact mutation plan.");
}
