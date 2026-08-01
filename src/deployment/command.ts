import { createInterface } from "node:readline";
import { asOpsHavenError, OpsHavenError } from "../errors.js";
import { colorEnabled, command, heading, section, statusLine } from "../operator-ui.js";
import { DeploymentExecutor } from "./apply.js";
import {
  DEPLOYMENT_BUILD_STRATEGY,
  DEPLOYMENT_ROLLBACK_BEHAVIOR,
  type ApplicationRegistrationInput,
  type DeploymentApplication,
  type DeploymentApplyResult,
  type DeploymentOperationKind,
  type StoredDeploymentPlan,
} from "./model.js";
import { DeploymentPlanner, type DeploymentRevisionChoice } from "./planning.js";

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
  return (process.stdin as { isTTY?: boolean }).isTTY === true && !args.includes("--non-interactive");
}

function writeFieldHelp(title: string, lines: readonly string[], color: boolean): void {
  process.stderr.write(`${section(title, color)}\n\n${lines.join("\n")}\n\n`);
}

function defaultApplicationName(id: string): string {
  if (id === "sample-api") return "Sample API";
  return id
    .split("-")
    .filter(Boolean)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ") || "Application";
}

function defaultRemoteTarget(planner: DeploymentPlanner): string {
  return [...planner.config.resources.values()]
    .filter((resource) => resource.kind === "host")
    .map((resource) => resource.id)
    .sort()[0] ?? "host.primary";
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

export function renderDeploymentApply(result: DeploymentApplyResult, color = colorEnabled()): string {
  const succeeded = result.outcome === "DEPLOYMENT_SUCCEEDED";
  const lines = [
    statusLine(succeeded ? "passed" : "failed", succeeded ? "Deployment succeeded" : "Deployment failed", undefined, color),
    "",
    section("Target", color),
    `  ${result.targetRevision}`,
  ];
  if (succeeded) {
    lines.push(
      "",
      section("Verification", color),
      statusLine("passed", "Service active", undefined, color),
      statusLine("passed", "Health check passed", undefined, color),
      statusLine("passed", "Target revision confirmed", undefined, color),
    );
  } else {
    const recoveryState = result.rollbackAttempted
      ? result.outcome === "DEPLOYMENT_FAILED_ROLLED_BACK" ? "rolled-back" : "failed"
      : "skipped";
    const recoveryLabel = result.rollbackAttempted
      ? result.outcome === "DEPLOYMENT_FAILED_ROLLED_BACK"
        ? "Previous release restored and verified"
        : "Previous release could not be verified"
      : "Rollback was not required because mutation did not begin";
    lines.push(
      "",
      section("Failure", color),
      `  ${result.failure ?? "Deployment verification failed."}`,
      "",
      section("Recovery", color),
      statusLine(recoveryState, recoveryLabel, undefined, color),
      "",
      section("Current revision", color),
      `  ${result.activeRevision}`,
    );
  }
  lines.push("", section("Outcome", color), `  ${result.outcome}`);
  return `${lines.join("\n")}\n`;
}

interface FailurePresentation {
  title: string;
  cause: string;
  changes: string;
  rollback: string;
  next: string;
  run?: string;
}

export interface DeploymentFailureContext {
  operation?: "plan" | "apply";
  applicationId?: string;
  revisionInput?: string;
}

function revisionFailure(error: unknown, context: DeploymentFailureContext, color: boolean): string | null {
  if (context.operation !== "plan") return null;
  const safe = asOpsHavenError(error);
  const applicationId = context.applicationId || "sample-api";
  const entered = context.revisionInput ?? "";
  const missing = entered.length === 0;
  const fingerprint = /^SHA256:/i.test(entered) || (entered.length >= 35 && /[^a-f0-9]/i.test(entered) && /^[A-Za-z0-9+/=]+$/.test(entered));
  const abbreviated = /^[a-f0-9]{4,39}$/i.test(entered);
  const branch = /^(?:main|master|head|latest|refs\/heads\/.+)$/i.test(entered);
  const tag = /^(?:refs\/tags\/.+|v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?)$/i.test(entered);
  const absent = /not verified in the configured repository|revision.*not.*repository|unknown revision/i.test(safe.message);
  const unavailable = /repository.*unavailable|repository.*missing|not a git repository|current release inspection|remote operation failed/i.test(safe.message);

  if (!missing && !fingerprint && !abbreviated && !branch && !tag && !absent && !unavailable && safe.code !== "INVALID_ARGUMENTS") return null;

  const lines = [
    statusLine("failed", "Deployment plan blocked", undefined, color),
    "",
    section("Cause", color),
    missing
      ? "No application revision was supplied."
      : fingerprint
        ? "The supplied value looks like a server identity fingerprint, not an application revision."
        : abbreviated
          ? "The supplied revision is abbreviated. OpsHaven requires the complete immutable commit ID."
          : branch
            ? "The supplied value is a moving branch or special Git reference."
            : tag
              ? "The supplied value is a tag, not a verified immutable commit ID."
              : absent
                ? "The supplied revision does not belong to the application's configured repository."
                : unavailable
                  ? "The configured application repository could not provide a verified revision."
                  : "The supplied revision is not a complete Git commit SHA.",
  ];

  if (!missing) {
    lines.push("", section("You entered", color), `  ${entered}`);
  }
  lines.push(
    "",
    section("Expected", color),
    "  One complete 40-character Git commit SHA.",
    "  It must contain only 0-9 and a-f and belong to this application's configured repository.",
    "",
    section("Example", color),
    "  0123456789abcdef0123456789abcdef01234567",
    "",
    section("What this means", color),
    "  A revision identifies one exact saved version of the application code.",
    "  OpsHaven uses immutable revisions so approved code cannot change later.",
  );
  if (fingerprint) {
    lines.push(
      "",
      section("Note", color),
      "  Values beginning with SHA256: are commonly server identity fingerprints.",
      "  They identify a server, not application code.",
    );
  }
  lines.push(
    "",
    section("Changes", color),
    "  No changes were made.",
    "",
    section("Rollback", color),
    "  Not required.",
    "",
    section("Next", color),
    unavailable
      ? "  Check that the registered remote repository is available, then choose a verified revision."
      : "  Choose a verified application revision:",
    "",
    command(unavailable ? "opshaven doctor" : `opshaven deploy plan ${applicationId}`, color),
  );
  return `${lines.join("\n")}\n`;
}

function genericFailure(error: unknown): FailurePresentation {
  const safe = asOpsHavenError(error);
  const unchanged = /stale|expired|digest mismatch|not explicitly approved|already applied|another deployment|revision must|not verified|audit chain|configuration changed/i.test(safe.message);
  if (/stale/i.test(safe.message)) {
    return {
      title: "Deployment plan is stale",
      cause: safe.message,
      changes: "No changes were made.",
      rollback: "Not required.",
      next: "Create a new deployment plan.",
    };
  }
  if (safe.code === "APPROVAL_REPLAYED" || /already applied|replay/i.test(safe.message)) {
    return {
      title: "Deployment plan replay blocked",
      cause: safe.message,
      changes: "No changes were made.",
      rollback: "Not required.",
      next: "Create a new deployment plan for any further deployment.",
    };
  }
  if (safe.code === "APPROVAL_REQUIRED" || safe.code === "APPROVAL_INVALID") {
    return {
      title: "Deployment approval rejected",
      cause: safe.message,
      changes: "No changes were made.",
      rollback: "Not required.",
      next: "Review and approve the exact stored deployment plan.",
    };
  }
  return {
    title: "Deployment operation blocked",
    cause: safe.message,
    changes: unchanged ? "No changes were made." : "The final remote state could not be confirmed. Recovery state remains authoritative.",
    rollback: unchanged ? "Not required." : "Inspect recovery state before another deployment.",
    next: /stale|expired/i.test(safe.message) ? "Create a new deployment plan." : "Check deployment readiness and correct the reported blocker.",
    ...(/stale|expired/i.test(safe.message) ? {} : { run: "opshaven doctor" }),
  };
}

export function renderDeploymentFailure(
  error: unknown,
  context: DeploymentFailureContext = {},
  color = colorEnabled(process.env, process.stderr),
): string {
  const revision = revisionFailure(error, context, color);
  if (revision) return revision;
  const value = genericFailure(error);
  const lines = [
    statusLine("failed", value.title, undefined, color),
    "",
    section("Cause", color),
    value.cause,
    "",
    section("Changes", color),
    value.changes,
    "",
    section("Rollback", color),
    value.rollback,
    "",
    section("Next", color),
    value.next,
  ];
  if (value.run) lines.push("", section("Run", color), command(value.run, color));
  return `${lines.join("\n")}\n`;
}

async function chooseRevision(
  planner: DeploymentPlanner,
  applicationId: string,
  color: boolean,
): Promise<string> {
  const choices = await planner.discoverRevisions(applicationId);
  process.stderr.write(`${heading("Choose an application revision", color)}\n\n`);
  process.stderr.write("A revision identifies one exact saved version of the application code.\n");
  process.stderr.write("OpsHaven requires a full Git commit SHA so approved code cannot later change because a branch or tag moved.\n\n");
  process.stderr.write(`${section("Available revisions", color)}\n\n`);
  choices.forEach((choice: DeploymentRevisionChoice, index: number) => {
    process.stderr.write(`${index + 1}. ${choice.revision}\n   ${choice.label}\n\n`);
  });
  const answer = await ask("Select revision", "1");
  if (!/^[1-9][0-9]*$/.test(answer)) {
    throw new OpsHavenError("INVALID_ARGUMENTS", "Revision selection must be one displayed number.");
  }
  const selected = choices[Number(answer) - 1];
  if (!selected) throw new OpsHavenError("INVALID_ARGUMENTS", "Revision selection is outside the displayed choices.");
  return selected.revision;
}

export interface RegistrationNext {
  kind: "plan" | "setup" | "doctor";
  command: string;
  revision?: string;
  revisionLabel?: string;
}

async function registrationNext(planner: DeploymentPlanner, app: DeploymentApplication): Promise<RegistrationNext> {
  try {
    const choices = await planner.discoverRevisions(app.id);
    const recommended = choices.find((choice) => choice.recommended) ?? choices[0];
    if (recommended) {
      return {
        kind: "plan",
        command: `opshaven deploy plan ${app.id} --revision ${recommended.revision}`,
        revision: recommended.revision,
        revisionLabel: recommended.label,
      };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/unknown resource|operator capability|policy version|authorization|remote configuration|incompatible remote resource/i.test(message)) {
      return { kind: "setup", command: "opshaven setup remote" };
    }
    if (/repository|revision|git/i.test(message)) {
      return { kind: "plan", command: `opshaven deploy plan ${app.id}` };
    }
  }
  return { kind: "doctor", command: "opshaven doctor" };
}

export function renderApplicationRegistration(
  app: DeploymentApplication,
  next: RegistrationNext,
  color = colorEnabled(),
): string {
  const lines = [
    statusLine("passed", "Application registered", undefined, color),
    "",
    section("Application", color),
    `  Name: ${app.name}`,
    `  ID: ${app.id}`,
    "",
    section("Remote target", color),
    `  ${app.targetLabel}`,
    "",
    section("Repository", color),
    `  ${app.repositoryLocation}`,
    "",
    section("Release location", color),
    `  ${app.releaseLocation}`,
    "",
    section("Deployment profile", color),
    "  Git checkout",
    "  Fixed npm build",
    "  Versioned releases",
    "  systemd restart",
    "  HTTP health verification",
    "",
    section("Recovery", color),
    "  Automatic previous-release restoration",
    ...(next.revision ? [
      "",
      section("Sample revision", color),
      `  ${next.revisionLabel ?? "Verified revision"}:`,
      `  ${next.revision}`,
    ] : []),
    "",
    section("Next", color),
    next.kind === "setup"
      ? "  Complete remote setup so the new application authorization is installed:"
      : next.kind === "plan" && next.revision
        ? "  Create a deployment plan for the verified sample revision:"
        : next.kind === "plan"
          ? "  Choose a verified application revision:"
          : "  Check deployment readiness:",
    "",
    command(next.command, color),
  ];
  return `${lines.join("\n")}\n`;
}

export async function runAppCommand(configPath: string, args: string[]): Promise<void> {
  if (args[0] !== "add") throw new OpsHavenError("INVALID_ARGUMENTS", "Unknown app command. Use opshaven app add.");
  const planner = await DeploymentPlanner.load(configPath);
  const guided = interactive(args);
  const color = colorEnabled(process.env, process.stderr);
  if (guided) {
    process.stderr.write(`${heading("Register a deployment application", color)}\n\n`);
    process.stderr.write("OpsHaven will register one reviewed Git, systemd, and HTTP deployment profile.\n\n");
    process.stderr.write("The defaults below configure the bundled synthetic sample application.\n");
    process.stderr.write("Press Enter at every prompt to use the sample safely.\n\n");
    process.stderr.write("Replace a value only when registering your own supported application.\n\n");
  }

  if (guided) writeFieldHelp("Application ID", [
    "The permanent lowercase name used in OpsHaven commands.",
    "Use lowercase letters, numbers, and hyphens.",
  ], color);
  const id = flag(args, "--id") ?? (guided ? await ask("Application ID", "sample-api") : "");

  if (guided) writeFieldHelp("Application name", [
    "The friendly label shown in reports and deployment output.",
  ], color);
  const name = flag(args, "--name") ?? (guided ? await ask("Application name", defaultApplicationName(id)) : "");

  if (guided) writeFieldHelp("Remote target", [
    "The configured remote machine where this application is deployed.",
    "Press Enter to use the current OpsHaven target.",
  ], color);
  const remoteTarget = flag(args, "--target") ?? (guided ? await ask("Remote target", defaultRemoteTarget(planner)) : "");

  if (guided) writeFieldHelp("Repository location", [
    "The absolute path to the Git repository on the remote machine.",
    "Press Enter to use the bundled synthetic sample repository.",
  ], color);
  const repositoryLocation = flag(args, "--repository") ?? (guided ? await ask("Repository location", `/srv/opshaven-fixtures/${id}/repository`) : "");

  if (guided) writeFieldHelp("Release location", [
    "The remote directory where versioned releases will be prepared.",
    "The active release is never built in place.",
  ], color);
  const releaseLocation = flag(args, "--releases") ?? (guided ? await ask("Release location", `/srv/opshaven-fixtures/${id}/releases`) : "");

  if (guided) writeFieldHelp("Service identifier", [
    "The approved systemd service OpsHaven may restart after activation.",
  ], color);
  const serviceIdentifier = flag(args, "--service") ?? (guided ? await ask("Service identifier", `${id}.service`) : "");

  if (guided) writeFieldHelp("Health check", [
    "The approved HTTP endpoint used to verify a successful deployment.",
    "The bundled sample uses a loopback-only endpoint on the remote machine.",
  ], color);
  const healthCheckUrl = flag(args, "--health-check") ?? (guided ? await ask("Health check", "http://127.0.0.1:3000/health") : "");

  const input: ApplicationRegistrationInput = {
    id,
    name,
    remoteTarget,
    repositoryLocation,
    releaseLocation,
    serviceIdentifier,
    healthCheckUrl,
    expectedStatus: Number(flag(args, "--expected-status") ?? "200"),
    buildStrategy: flag(args, "--build-strategy") ?? DEPLOYMENT_BUILD_STRATEGY,
    rollbackBehavior: flag(args, "--rollback") ?? DEPLOYMENT_ROLLBACK_BEHAVIOR,
  };

  if (guided) {
    process.stderr.write(`${section("Review", color)}\n\n`);
    process.stderr.write(`  Name: ${input.name}\n  ID: ${input.id}\n  Remote target: ${input.remoteTarget}\n  Repository: ${input.repositoryLocation}\n  Releases: ${input.releaseLocation}\n  Service: ${input.serviceIdentifier}\n  Health: ${input.healthCheckUrl}\n\n`);
    process.stderr.write("No arbitrary commands or deployment hooks will be added.\n\n");
    if (!(await confirm("Create this application registration?"))) {
      process.stdout.write(args.includes("--json")
        ? `${JSON.stringify({ ok: false, cancelled: true, changed: false })}\n`
        : `${statusLine("warning", "Application registration cancelled", "No changes were made", colorEnabled())}\n`);
      return;
    }
  } else if (!args.includes("--approve")) {
    throw new OpsHavenError("APPROVAL_REQUIRED", "Non-interactive application registration requires --approve.");
  }

  const app = await planner.registerApplication(input);
  const refreshed = await DeploymentPlanner.load(configPath);
  const next = await registrationNext(refreshed, app);
  if (args.includes("--json")) {
    process.stdout.write(`${JSON.stringify({ ok: true, application: app, next })}\n`);
  } else {
    process.stdout.write(renderApplicationRegistration(app, next));
  }
}

export async function runDeployCommand(configPath: string, args: string[]): Promise<void> {
  try {
    const planner = await DeploymentPlanner.load(configPath);
    if (args[0] === "plan") {
      const applicationId = args[1] ?? "";
      let revision = flag(args, "--revision") ?? "";
      if (!revision) {
        if (!interactive(args) || args.includes("--json")) {
          throw new OpsHavenError(
            "INVALID_ARGUMENTS",
            "A complete revision is required for non-interactive and JSON deployment planning.",
          );
        }
        revision = await chooseRevision(planner, applicationId, colorEnabled(process.env, process.stderr));
      }
      const stored = await planner.createPlan(applicationId, revision);
      process.stdout.write(args.includes("--json") ? `${JSON.stringify({ ok: true, ...stored })}\n` : renderPlan(stored));
      return;
    }
    if (args[0] === "apply") {
      const planId = args[1] ?? "";
      await planner.plans.load(planId);
      let token = flag(args, "--approval-token") ?? process.env.OPSHAVEN_APPROVAL_TOKEN;
      let approved = typeof token === "string" && token.length > 0;
      if (interactive(args)) {
        const color = colorEnabled(process.env, process.stderr);
        process.stderr.write(`${heading(`Apply deployment plan ${planId}?`, color)}\n\n`);
        process.stderr.write("This will:\n  create one release\n  switch the active release\n  restart one approved service\n\n");
        process.stderr.write(`${statusLine("passed", "Rollback is prepared", undefined, color)}\n\n`);
        approved = await confirm("Continue?");
      }
      if (!approved) {
        process.stdout.write(args.includes("--json")
          ? `${JSON.stringify({ ok: false, cancelled: true, changed: false, planId })}\n`
          : `${statusLine("warning", "Deployment cancelled", "No changes were made", colorEnabled())}\n`);
        return;
      }
      const result = await new DeploymentExecutor(planner).apply(planId, { approved: true, ...(token ? { approvalToken: token } : {}) });
      token = undefined;
      process.stdout.write(args.includes("--json") ? `${JSON.stringify({ ok: result.outcome === "DEPLOYMENT_SUCCEEDED", result })}\n` : renderDeploymentApply(result));
      process.exitCode = result.outcome === "DEPLOYMENT_SUCCEEDED" ? 0 : 1;
      return;
    }
    throw new OpsHavenError("INVALID_ARGUMENTS", "Unknown deploy command. Use opshaven deploy plan or opshaven deploy apply.");
  } catch (error) {
    if (args.includes("--debug")) throw error;
    if (args.includes("--json")) {
      const safe = asOpsHavenError(error);
      process.stderr.write(`${JSON.stringify({ ok: false, error: { code: safe.code, message: safe.message }, changed: false })}\n`);
    } else {
      const context: DeploymentFailureContext = {
        ...(args[0] === "plan" ? { operation: "plan" as const } : args[0] === "apply" ? { operation: "apply" as const } : {}),
        ...(args[1] ? { applicationId: args[1] } : {}),
        revisionInput: flag(args, "--revision") ?? "",
      };
      process.stderr.write(renderDeploymentFailure(error, context));
    }
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
