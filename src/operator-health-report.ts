import { colorEnabled, command, heading, section, statusLine } from "./operator-ui.js";
import { inspectInstallationHealth, type InstallationHealthReport } from "./setup/health.js";
import type { RemoteSetupConfig } from "./setup/remote.js";

export interface CanonicalHealthDoctorReport {
  readonly ok: false;
  readonly state: "REMOTE_REPAIR_REQUIRED";
  readonly primary: InstallationHealthReport["primary"];
  readonly states: InstallationHealthReport["states"];
  readonly repairClassification: InstallationHealthReport["repairClassification"];
  readonly reasons: InstallationHealthReport["reasons"];
  readonly nextAction: string;
  readonly health: InstallationHealthReport;
}

function scalar(value: unknown): string {
  if (value === null || value === undefined) return "unavailable";
  if (Array.isArray(value)) return value.length > 0 ? value.join(", ") : "none";
  return String(value);
}

export function formatCanonicalHealthDoctor(report: CanonicalHealthDoctorReport, debug: boolean): string {
  const color = colorEnabled();
  const health = report.health;
  const lines = [
    heading("OpsHaven Health", color),
    "",
    section("Remote installation", color),
    statusLine("failed", "Repair required", health.reasons[0] ?? "Installed generation evidence cannot be verified completely", color),
    "",
    section("Canonical state", color),
    `Health\n  ${health.primary}`,
    `Repair classification\n  ${health.repairClassification}`,
    `Receipt validity\n  ${health.receiptValidity}`,
    `Migration status\n  ${health.migrationStatus}`,
    `Rollback material\n  ${health.transaction.rollbackAvailable ? "available and integrity-checked" : "unavailable or invalid"}`,
    "",
    section("Deployment", color),
    statusLine("failed", "Planning and apply blocked", "Repair the installation before creating or applying an exact deployment plan", color),
    "",
    section("Boundary certification", color),
    statusLine("failed", "Certification blocked", "The active generation identity is incomplete or uncertain", color),
    "",
    section("Next", color),
    command(report.nextAction, color),
  ];
  if (debug) {
    lines.push(
      "",
      section("Sanitized health details", color),
      `Active generation\n  ${scalar(health.activeGeneration)}`,
      `Previous generation\n  ${scalar(health.previousGenerationIdentity)}`,
      `Transaction status\n  ${health.transaction.status}`,
      `Transaction phase\n  ${scalar(health.transaction.lastCompletedPhase)}`,
      `Receipt validity\n  ${health.receiptValidity}`,
      `Runtime digest\n  ${scalar(health.installed.runtimeSha256)}`,
      `Dispatcher digest\n  ${scalar(health.installed.dispatcherSha256)}`,
      `Authorization digest\n  ${scalar(health.installed.capabilityIdentitySha256)}`,
      `Application scope\n  ${scalar(health.installed.applicationScope)}`,
      `Managed footprint\n  ${scalar(health.footprint?.kind)}`,
      `Migration status\n  ${health.migrationStatus}`,
      `Repair classification\n  ${health.repairClassification}`,
    );
  }
  return `${lines.join("\n")}\n`;
}

export async function runCanonicalHealthDoctor(config: RemoteSetupConfig, args: readonly string[]): Promise<boolean> {
  const health = await inspectInstallationHealth(config);
  if (!health.repairRequired) return false;
  const report: CanonicalHealthDoctorReport = Object.freeze({
    ok: false,
    state: "REMOTE_REPAIR_REQUIRED",
    primary: health.primary,
    states: health.states,
    repairClassification: health.repairClassification,
    reasons: health.reasons,
    nextAction: health.safeNextCommand ?? "opshaven setup repair",
    health,
  });
  process.stdout.write(args.includes("--json") ? `${JSON.stringify(report)}\n` : formatCanonicalHealthDoctor(report, args.includes("--debug")));
  process.exitCode = 1;
  return true;
}
