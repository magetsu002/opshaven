import { createInterface } from "node:readline";
import { OpsHavenError } from "../errors.js";
import { colorEnabled, command, heading, section, statusLine } from "../operator-ui.js";
import { DeploymentExecutor } from "./apply.js";
import {
  DEPLOYMENT_BUILD_STRATEGY,
  DEPLOYMENT_ROLLBACK_BEHAVIOR,
  type ApplicationRegistrationInput,
  type DeploymentApplyResult,
  type DeploymentOperationKind,
  type StoredDeploymentPlan,
} from "./model.js";
import { DeploymentPlanner } from "./planning.js";

function flag(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}

async function ask(question: string, fallback = ""): Promise<string> {
  const input = createInterface({ input: process.stdin, output: process.stderr });
  return await new Promise((resolve) => input.question(`${question}${fallback ? ` [${fallback}]` : ""}: `, (answer: string) => {
    input.close();
    resolve(answer.trim() || fallback);
  }));
}

async function confirm(question: string): Promise<boolean> {
  const answer = await ask(`${question} [y/N]`);
  return answer === "y" || answer === "Y";
}

function interactive(args: readonly string[]): boolean {
  return (process.stdin as any).isTTY === true && !args.includes("--non-interactive");
}

function renderPlan(stored: StoredDeploymentPlan): string {
  const color = colorEnabled();
  const labels: Record<DeploymentOperationKind, string> = {
    verify_revision: "Verify target revision",
    inspect_current_release: "Inspect current release",
    check_disk_space: "Check available disk space",
    prepare_release: "Prepare a versioned release",
    fetch_verified_source: "Prepare exact verified source",
    build_release: "Build with the fixed profile",
    record_rollback_point: "Record rollback point",
    activate_release: "Activate release atomically",
    restart_service: "Restart approved service",
    run_health_check: "Check application health",
    confirm_revision: "Confirm deployed revision",
    restore_release: "Restore previous release",
  };
  const plan = stored.plan;
  const lines = [
    heading("OpsHaven Deployment Plan", color), "",
    section("Application", color), `  ${plan.applicationId}`,
    section("Target", color), `  ${plan.target.label}`,
    section("Observed state", color), `  Current release: ${plan.observed.activeReleaseId}`, `  Service: ${plan.observed.serviceActiveState}`, `  Health: ${plan.observed.healthExpected ? "healthy" : "blocked"}`,
    section("Revision", color), `  Current: ${plan.currentRevision}`, `  Target:  ${plan.targetRevision}`,
    section("Operations", color),
  ];
  plan.operations.forEach((operation, index) => lines.push(`  ${index + 1}. ${labels[operation.kind]}`));
  lines.push(
    section("Verification", color), "  Service active", "  Health status accepted", "  Exact target revision active",
    section("Rollback", color), `  Restore ${plan.rollback.releaseId}`, "  Restart approved service", "  Recheck health and previous revision",
    section("Risk", color), "  Mutates application release state", `  Restarts ${plan.risk.restartsApprovedServices.join(", ")}`, "  Database migrations are unsupported",
    section("Expiration", color), `  ${plan.expiresAt}`,
    section("Plan ID", color), `  ${stored.planId}`, "", statusLine("passed", "No changes were made", undefined, color), "",
    section("Next", color), command(`opshaven deploy apply ${stored.planId}`, color),
  );
  return `${lines.join("\n")}\n`;
}

function renderApply(result: DeploymentApplyResult): string {
  if (result.outcome === "DEPLOYMENT_SUCCEEDED") return `Deployment succeeded\nTarget\n  ${result.targetRevision}\nVerification\n  ✓ Service active\n  ✓ Health check passed\n  ✓ Target revision confirmed\nOutcome\n  ${result.outcome}\n`;
  const recovery = result.rollbackAttempted
    ? result.outcome === "DEPLOYMENT_FAILED_ROLLED_BACK" ? "  ✓ Previous release restored and verified" : "  ✗ Previous release could not be verified"
    : "  Rollback was not required because mutation did not begin";
  return `Deployment failed safely\nTarget\n  ${result.targetRevision}\nFailure\n  ${result.failure ?? "Deployment verification failed."}\nRecovery\n${recovery}\nCurrent revision\n  ${result.activeRevision}\nOutcome\n  ${result.outcome}\n`;
}

function renderFailure(error: unknown): string {
  const message = error instanceof Error ? error.message : "Deployment operation failed safely.";
  const unchanged = /stale|expired|digest mismatch|not explicitly approved|already applied|another deployment|revision must|not verified|audit chain|configuration changed/i.test(message);
  return `${/stale/i.test(message) ? "Deployment plan is stale." : "Deployment operation blocked."}\nCause\n${message}\nChanges\n${unchanged ? "No changes were made." : "The final remote state could not be confirmed. Recovery state remains authoritative."}\nRollback\n${unchanged ? "Not required." : "Inspect recovery state before another deployment."}\nNext\n${/stale|expired/i.test(message) ? "Create a new deployment plan." : "Run opshaven doctor and correct the reported blocker."}\n`;
}

export async function runAppCommand(configPath: string, args: string[]): Promise<void> {
  if (args[0] !== "add") throw new OpsHavenError("INVALID_ARGUMENTS", "Unknown app command. Use opshaven app add.");
  const guided = interactive(args);
  const id = flag(args, "--id") ?? (guided ? await ask("Application ID", "sample-api") : "");
  const input: ApplicationRegistrationInput = {
    id,
    name: flag(args, "--name") ?? (guided ? await ask("Application name", id) : ""),
    remoteTarget: flag(args, "--target") ?? (guided ? await ask("Remote target", "host.primary") : ""),
    repositoryLocation: flag(args, "--repository") ?? (guided ? await ask("Repository location", `/srv/opshaven-fixtures/${id}/repository`) : ""),
    releaseLocation: flag(args, "--releases") ?? (guided ? await ask("Release location", `/srv/opshaven-fixtures/${id}/releases`) : ""),
    serviceIdentifier: flag(args, "--service") ?? (guided ? await ask("Service identifier", `${id}.service`) : ""),
    healthCheckUrl: flag(args, "--health-check") ?? (guided ? await ask("Health check", "http://127.0.0.1:3000/health") : ""),
    expectedStatus: Number(flag(args, "--expected-status") ?? "200"),
    buildStrategy: flag(args, "--build-strategy") ?? DEPLOYMENT_BUILD_STRATEGY,
    rollbackBehavior: flag(args, "--rollback") ?? DEPLOYMENT_ROLLBACK_BEHAVIOR,
  };
  if (guided) {
    process.stderr.write("\nOpsHaven will add one fixed Git/systemd/HTTP deployment profile. No arbitrary commands or hooks will be added.\n\n");
    if (!(await confirm("Create this application registration?"))) {
      process.stdout.write(args.includes("--json") ? `${JSON.stringify({ ok: false, cancelled: true, changed: false })}\n` : "Application registration cancelled. No changes were made.\n");
      return;
    }
  } else if (!args.includes("--approve")) throw new OpsHavenError("APPROVAL_REQUIRED", "Non-interactive application registration requires --approve.");
  const app = await (await DeploymentPlanner.load(configPath)).registerApplication(input);
  if (args.includes("--json")) process.stdout.write(`${JSON.stringify({ ok: true, application: app, next: "opshaven setup remote" })}\n`);
  else process.stdout.write(`Application registered\nApplication\n  ${app.name} (${app.id})\nTarget\n  ${app.targetLabel}\nProfile\n  Git checkout, fixed npm build, versioned releases, systemd restart, HTTP health check\nRollback\n  Automatic previous-release restoration\nNext\n  opshaven setup remote\n  opshaven deploy plan ${app.id} --revision <full-commit-sha>\n`);
}

export async function runDeployCommand(configPath: string, args: string[]): Promise<void> {
  try {
    const planner = await DeploymentPlanner.load(configPath);
    if (args[0] === "plan") {
      const stored = await planner.createPlan(args[1] ?? "", flag(args, "--revision") ?? "");
      process.stdout.write(args.includes("--json") ? `${JSON.stringify({ ok: true, ...stored })}\n` : renderPlan(stored));
      return;
    }
    if (args[0] === "apply") {
      const planId = args[1] ?? "";
      await planner.plans.load(planId);
      let token = flag(args, "--approval-token") ?? process.env.OPSHAVEN_APPROVAL_TOKEN;
      let approved = typeof token === "string" && token.length > 0;
      if (interactive(args)) {
        process.stderr.write(`Apply deployment plan ${planId}?\nThis will:\n  create one release\n  switch the active release\n  restart one approved service\nRollback is prepared.\n`);
        approved = await confirm("Continue?");
      }
      if (!approved) {
        process.stdout.write(args.includes("--json") ? `${JSON.stringify({ ok: false, cancelled: true, changed: false, planId })}\n` : "Deployment cancelled. No changes were made.\n");
        return;
      }
      const result = await new DeploymentExecutor(planner).apply(planId, { approved: true, ...(token ? { approvalToken: token } : {}) });
      token = undefined;
      process.stdout.write(args.includes("--json") ? `${JSON.stringify({ ok: result.outcome === "DEPLOYMENT_SUCCEEDED", result })}\n` : renderApply(result));
      process.exitCode = result.outcome === "DEPLOYMENT_SUCCEEDED" ? 0 : 1;
      return;
    }
    throw new OpsHavenError("INVALID_ARGUMENTS", "Unknown deploy command. Use opshaven deploy plan or opshaven deploy apply.");
  } catch (error) {
    if (args.includes("--debug")) throw error;
    process.stderr.write(renderFailure(error));
    process.exitCode = 1;
  }
}

export async function runDeploymentDoctor(configPath: string, args: string[]): Promise<void> {
  if (!configPath || args.includes("--json")) return;
  const color = colorEnabled();
  process.stdout.write(`\n${section("Deployment", color)}\n`);
  try {
    const report = await (await DeploymentPlanner.load(configPath)).deploymentDoctor();
    for (const item of report.checks) process.stdout.write(`${statusLine(item.passed ? "passed" : "failed", item.label, item.detail, color)}\n`);
    process.stdout.write(`${section("Next", color)}\n${command(report.next, color)}\n`);
    if (report.checks.some((item) => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stdout.write(`${statusLine("failed", "Deployment readiness", error instanceof Error ? error.message : "verification failed safely", color)}\n${section("Next", color)}\n${command("opshaven app add", color)}\n`);
    process.exitCode = 1;
  }
}
