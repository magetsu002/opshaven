import { promises as fs } from "node:fs";
import { verifyBoundary, type BoundaryReport } from "./boundary.js";
import { loadConfig } from "./config.js";
import { inspectOperatorState } from "./operator-state.js";
import { colorEnabled, command, heading, sanitizeOperatorText, section, statusLine } from "./operator-ui.js";
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
  const sanitized = sanitizeOperatorText(raw);
  return /^[A-Za-z0-9 .,:;()'"_<>-]{1,240}$/.test(sanitized) ? sanitized : "verification did not complete";
}

function check(label: string, passed: boolean, detail?: string): DoctorCheck {
  return detail === undefined ? { label, passed } : { label, passed, detail };
}

function assertionPassed(report: BoundaryReport | null, name: string): boolean {
  return report?.assertions.find((item) => item.name === name)?.passed === true;
}

function renderChecks(title: string, checks: readonly DoctorCheck[], color: boolean): string[] {
  const lines = [section(title, color)];
  if (checks.length === 0) lines.push(statusLine("skipped", "Not checked", undefined, color));
  else for (const item of checks) lines.push(statusLine(item.passed ? "passed" : "failed", item.label, item.detail, color));
  return lines;
}

export function formatDoctorReport(report: DoctorReport): string {
  const color = colorEnabled();
  const lines: string[] = [heading("OpsHaven Health", color), ""];
  lines.push(...renderChecks("Local environment", report.localOperatorEnvironment, color), "");
  lines.push(...renderChecks("Remote connection", report.remoteDeploymentState, color), "");
  lines.push(...renderChecks("Authorization state", report.authorizationArtifacts, color), "");
  lines.push(...renderChecks("Security verification", [...report.endpointReadiness, ...report.securityBoundaryStatus], color), "");
  lines.push(section("Next action", color));
  lines.push(report.ok ? "No action required." : command("opshaven doctor --debug", color));
  return `${lines.join("\n")}\n`;
}

function has(completed: readonly string[], value: string): boolean {
  return completed.includes(value);
}

export function formatWorkflowReport(report: OperatorWorkflowReport): string {
  const color = colorEnabled();
  const localReady = has(report.completed, "Operator keys") && has(report.completed, "Local configuration");
  const remoteConfigured = report.state === "REMOTE_CONFIGURED" || report.state === "READY" || has(report.completed, "Remote setup state");
  const remoteReady = report.state === "READY" || has(report.completed, "Remote deployment");
  const verified = report.state === "READY" || has(report.completed, "Boundary verification");
  const blocked = report.blocked[0];
  const lines = [heading("OpsHaven Health", color), ""];
  lines.push(section("Local environment", color));
  lines.push(statusLine(localReady ? "passed" : "failed", localReady ? "Operator setup ready" : "Operator setup incomplete", localReady ? undefined : blocked, color), "");
  lines.push(section("Remote connection", color));
  lines.push(statusLine(remoteReady ? "passed" : remoteConfigured ? "warning" : "failed", remoteReady ? "Remote machine reachable" : remoteConfigured ? "Remote setup requires attention" : "Remote setup not configured", remoteReady ? undefined : blocked, color), "");
  lines.push(section("Authorization state", color));
  lines.push(statusLine(report.state === "READY" ? "passed" : localReady ? "warning" : "failed", report.state === "READY" ? "Authorization valid" : localReady ? "Waiting for remote verification" : "Authorization not ready", undefined, color), "");
  lines.push(section("Security verification", color));
  lines.push(statusLine(verified ? "passed" : "skipped", verified ? "Security boundary verified" : "Not yet verified", undefined, color), "");
  lines.push(section("Next action", color));
  lines.push(report.nextAction ? command(report.nextAction, color) : "No action required.");
  if (report.details) lines.push("", section("Debug details", color), "", formatDoctorReport(report.details).trimEnd());
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
    check("Operator SSH key available", hosts.length > 0 && hostFiles.every((item) => item.identity)),
    check("Pinned host identity available", hosts.length > 0 && hostFiles.every((item) => item.knownHosts)),
    check("Authorization signing available", approvalPrivateKey),
    check("Authorization verification available", approvalPublicKey),
    check("Replay protection available", approvalSecret),
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
      check("Remote connection available", authenticatedInspection, boundaryError || undefined),
      check("Remote runtime verified", authenticatedInspection, boundaryError || undefined),
    ],
    authorizationArtifacts: [
      check("Authorization valid", authenticatedInspection, boundaryError || undefined),
      check("Deployment authorization valid", authenticatedInspection, boundaryError || undefined),
    ],
    endpointReadiness: [
      check("Endpoint configuration valid", endpointConfigurationValid, endpointError || undefined),
      check(endpointEnabled ? "Remote endpoint is read-only" : "Local connection mode selected", endpointEnabled ? endpointReadOnly : true),
    ],
    securityBoundaryStatus: [
      check("Security boundary verified", boundaryValid, boundaryError || undefined),
      check("Audit history valid", auditValid, boundaryError || undefined),
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
