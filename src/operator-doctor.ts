import { promises as fs } from "node:fs";
import { verifyBoundary, type BoundaryReport } from "./boundary.js";
import { loadConfig } from "./config.js";
import { inspectOperatorState } from "./operator-state.js";
import { loadRemoteTrust } from "./remote-mcp/report.js";

export interface DoctorCheck {
  label: string;
  passed: boolean;
  detail?: string;
}

export interface DoctorReport {
  ok: boolean;
  mode: "controlled" | "read-only";
  localOperatorEnvironment: DoctorCheck[];
  remoteDeploymentState: DoctorCheck[];
  authorizationArtifacts: DoctorCheck[];
  endpointReadiness: DoctorCheck[];
  securityBoundaryStatus: DoctorCheck[];
  endpoint: "READY" | "BLOCKED";
}

export type OperatorWorkflowState = "NOT_INITIALIZED" | "LOCAL_INITIALIZED" | "REMOTE_CONFIGURED" | "READY" | "BLOCKED";

export interface OperatorWorkflowReport {
  ok: boolean;
  state: OperatorWorkflowState;
  completed: string[];
  blocked: string[];
  nextAction: string | null;
  details?: DoctorReport;
}

function selectedMode(args: string[]): "controlled" | "read-only" {
  const index = args.indexOf("--mode");
  const mode = index >= 0 ? args[index + 1] : "read-only";
  if (mode !== "controlled" && mode !== "read-only") throw new Error("Mode must be controlled or read-only.");
  return mode;
}

async function regularFile(path: string, ownerOnly: boolean): Promise<boolean> {
  try {
    const stat = await fs.lstat(path);
    return stat.isFile() && !stat.isSymbolicLink() && (!ownerOnly || (stat.mode & 0o077) === 0);
  } catch {
    return false;
  }
}

function safeDetail(error: unknown): string {
  const raw = error instanceof Error ? error.message : "verification did not complete";
  const sanitized = raw.replace(/\/[A-Za-z0-9._/-]+/g, "<protected path>");
  return /^[A-Za-z0-9 .,:;()'"_<>-]{1,240}$/.test(sanitized) ? sanitized : "verification did not complete";
}

function check(label: string, passed: boolean, detail?: string): DoctorCheck {
  return detail === undefined ? { label, passed } : { label, passed, detail };
}

function assertionPassed(report: BoundaryReport | null, name: string): boolean {
  return report?.assertions.find((item) => item.name === name)?.passed === true;
}

export function formatDoctorReport(report: DoctorReport): string {
  const lines: string[] = [];
  const section = (title: string, checks: DoctorCheck[]): void => {
    lines.push(title, "");
    for (const item of checks) lines.push(`${item.passed ? "✓" : "✗"} ${item.label}${item.detail ? ` — ${item.detail}` : ""}`);
    lines.push("");
  };
  section("Local operator environment", report.localOperatorEnvironment);
  section("Remote deployment state", report.remoteDeploymentState);
  section("Authorization artifacts", report.authorizationArtifacts);
  section("Endpoint readiness", report.endpointReadiness);
  section("Security boundary status", report.securityBoundaryStatus);
  lines.push("Endpoint:", report.endpoint);
  return `${lines.join("\n")}\n`;
}

export function formatWorkflowReport(report: OperatorWorkflowReport): string {
  const lines = ["Current state:", report.state, "", "Completed:"];
  if (report.completed.length === 0) lines.push("None");
  else for (const item of report.completed) lines.push(`✓ ${item}`);
  lines.push("", "Blocked:");
  if (report.blocked.length === 0) lines.push("None");
  else for (const item of report.blocked) lines.push(`✗ ${item}`);
  lines.push("", "Next action:", report.nextAction ?? "No action required.");
  if (report.details) lines.push("", "Debug details:", "", formatDoctorReport(report.details).trimEnd());
  return `${lines.join("\n")}\n`;
}

async function buildDoctorReport(configPath: string, args: string[]): Promise<DoctorReport> {
  const mode = selectedMode(args);
  const config = await loadConfig(configPath);
  const hosts = [...config.resources.values()].filter((item) => item.kind === "host");
  const hostFiles = await Promise.all(hosts.map(async (host) => ({
    knownHosts: await regularFile(host.knownHostsFile, false),
    identity: await regularFile(host.identityFile, true),
  })));
  const approvalSecret = await regularFile(config.approvals.secretFile, true);
  const approvalPrivateKey = await regularFile(config.approvals.signingPrivateKeyFile, true);
  const approvalPublicKey = await regularFile(config.approvals.verificationPublicKeyFile, false);
  const localChecks = [
    check("Configured host identity available", hosts.length > 0 && hostFiles.every((item) => item.identity)),
    check("Pinned host-key file available", hosts.length > 0 && hostFiles.every((item) => item.knownHosts)),
    check("Approval signing key available", approvalPrivateKey),
    check("Approval verification key available", approvalPublicKey),
    check("Approval replay secret available", approvalSecret),
  ];
  const localOk = localChecks.every((item) => item.passed);

  let endpointConfigurationValid = false;
  let endpointReadOnly = false;
  let endpointEnabled = false;
  let endpointError = "";
  try {
    const remote = await loadRemoteTrust(configPath, config);
    endpointConfigurationValid = remote.assertions.every((item: { passed: boolean }) => item.passed);
    endpointReadOnly = remote.summary.readOnly;
    endpointEnabled = remote.summary.enabled;
  } catch (error) {
    endpointError = safeDetail(error);
  }

  let boundary: BoundaryReport | null = null;
  let boundaryError = "";
  if (localOk) {
    try {
      boundary = await verifyBoundary(config, configPath, mode);
    } catch (error) {
      boundaryError = safeDetail(error);
    }
  } else {
    boundaryError = "local prerequisites are incomplete";
  }

  const authenticatedInspection = assertionPassed(boundary, "artifact and capability hashes valid");
  const auditValid = assertionPassed(boundary, "audit chain valid");
  const boundaryValid = boundary?.ok === true;
  return {
    ok: localOk && authenticatedInspection && endpointConfigurationValid && boundaryValid,
    mode,
    localOperatorEnvironment: localChecks,
    remoteDeploymentState: [
      check("Remote host reachable", authenticatedInspection, boundaryError || undefined),
      check("Runtime attestation matches", authenticatedInspection, boundaryError || undefined),
    ],
    authorizationArtifacts: [
      check("Capability authorization valid", authenticatedInspection, boundaryError || undefined),
      check("Signed policy artifacts valid", authenticatedInspection, boundaryError || undefined),
    ],
    endpointReadiness: [
      check("Endpoint policy valid", endpointConfigurationValid, endpointError || undefined),
      check(endpointEnabled ? "Remote endpoint is read-only" : "Local stdio mode selected", endpointEnabled ? endpointReadOnly : true),
    ],
    securityBoundaryStatus: [
      check("Boundary verification passed", boundaryValid, boundaryError || undefined),
      check("Audit chain valid", auditValid, boundaryError || undefined),
    ],
    endpoint: localOk && authenticatedInspection && endpointConfigurationValid && boundaryValid ? "READY" : "BLOCKED",
  };
}

function initialReport(initialized: boolean, keysReady: boolean, localReady: boolean): OperatorWorkflowReport {
  if (!initialized) {
    return {
      ok: false,
      state: "NOT_INITIALIZED",
      completed: [],
      blocked: ["Local operator setup has not been initialized"],
      nextAction: "opshaven init",
    };
  }
  const completed = [
    ...(keysReady ? ["Operator keys"] : []),
    ...(localReady ? ["Local configuration"] : []),
  ];
  return {
    ok: false,
    state: keysReady && localReady ? "LOCAL_INITIALIZED" : "BLOCKED",
    completed,
    blocked: keysReady && localReady ? ["Remote deployment not configured"] : ["Local operator setup needs repair"],
    nextAction: keysReady && localReady ? "opshaven setup remote" : "opshaven init",
  };
}

export async function runDoctor(configPath: string, args: string[]): Promise<void> {
  const debug = args.includes("--debug");
  let snapshot;
  try {
    snapshot = await inspectOperatorState(args);
  } catch {
    snapshot = {
      initialized: false,
      keysReady: false,
      localConfigurationReady: false,
      remoteConfigured: false,
      setupReady: false,
      configPath: null,
      setupPath: null,
    };
  }
  if (!configPath) {
    const report = initialReport(snapshot.initialized, snapshot.keysReady, snapshot.localConfigurationReady);
    if (args.includes("--json")) process.stdout.write(`${JSON.stringify(report)}\n`);
    else process.stdout.write(formatWorkflowReport(report));
    process.exitCode = 1;
    return;
  }

  let details: DoctorReport;
  try {
    details = await buildDoctorReport(configPath, args);
  } catch (error) {
    const report: OperatorWorkflowReport = {
      ok: false,
      state: "BLOCKED",
      completed: [
        ...(snapshot.keysReady ? ["Operator keys"] : []),
        "Local configuration",
      ],
      blocked: ["Operator readiness checks could not complete"],
      nextAction: snapshot.initialized ? "opshaven init" : "opshaven doctor --debug --config <path>",
      ...(debug ? { details: {
        ok: false,
        mode: selectedMode(args),
        localOperatorEnvironment: [check("Diagnostic execution", false, safeDetail(error))],
        remoteDeploymentState: [],
        authorizationArtifacts: [],
        endpointReadiness: [],
        securityBoundaryStatus: [],
        endpoint: "BLOCKED",
      } } : {}),
    };
    if (args.includes("--json")) process.stdout.write(`${JSON.stringify(report)}\n`);
    else process.stdout.write(formatWorkflowReport(report));
    process.exitCode = 1;
    return;
  }

  const ready = details.ok;
  const managedState = snapshot.initialized;
  const report: OperatorWorkflowReport = {
    ok: ready,
    state: ready ? "READY" : managedState ? "REMOTE_CONFIGURED" : "BLOCKED",
    completed: [
      ...(snapshot.keysReady ? ["Operator keys"] : []),
      "Local configuration",
      ...(snapshot.setupReady ? ["Remote setup state"] : []),
      ...(ready ? ["Remote deployment", "Boundary verification"] : []),
    ],
    blocked: ready ? [] : ["Remote deployment is not ready"],
    nextAction: ready ? null : managedState ? "opshaven setup remote" : "opshaven doctor --debug --config <path>",
    ...(debug ? { details } : {}),
  };
  if (args.includes("--json")) process.stdout.write(`${JSON.stringify(report)}\n`);
  else process.stdout.write(formatWorkflowReport(report));
  process.exitCode = report.ok ? 0 : 1;
}
