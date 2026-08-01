import { OpsHavenError } from "./errors.js";
import { formatOperatorFailure, sanitizeOperatorText } from "./operator-ui.js";

function debugEnabled(args: readonly string[]): boolean {
  return args.includes("--debug") || process.argv.includes("--debug") || process.env.OPSHAVEN_DEBUG === "1";
}

function preflightCause(raw: string): string {
  if (/ssh-connectivity/i.test(raw)) return "Administrator SSH authentication failed or the remote machine could not be reached.";
  if (/host-key-fingerprint/i.test(raw)) return "The pinned SSH host identity did not match the verified fingerprint.";
  if (/remote-platform/i.test(raw)) return "The remote operating system is not supported.";
  if (/remote-node/i.test(raw)) return "A supported Node.js runtime was not found on the remote machine.";
  if (/remote-privilege/i.test(raw)) return "The administrator account does not have the required installation permission.";
  return "One or more remote installation checks failed.";
}

function detail(error: OpsHavenError, key: string): unknown {
  return error.safeDetails?.[key];
}

function safeScalar(value: unknown, fallback = "unknown"): string {
  if (typeof value === "string" && value.length > 0) return value.replace(/[\r\n\u001b\u009b]/g, " ").slice(0, 240);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function synchronizationFailure(error: OpsHavenError, debug: boolean): string | null {
  const outcome = detail(error, "setupOutcome");
  if (outcome !== "SETUP_FAILED_ROLLED_BACK" && outcome !== "SETUP_CANCELLED_ROLLED_BACK" && outcome !== "SETUP_FAILED_ROLLBACK_FAILED") return null;
  const failedStage = safeScalar(detail(error, "failedVerificationStage"), "active-generation verification");
  const active = safeScalar(detail(error, "activeGeneration"), outcome === "SETUP_FAILED_ROLLBACK_FAILED" ? "uncertain" : "previous verified generation");
  const previous = safeScalar(detail(error, "previousGeneration"), "unavailable");
  const mutation = detail(error, "mutationStarted") === true;
  const rollbackStarted = detail(error, "rollbackStarted") === true;
  const rollbackCompleted = detail(error, "rollbackCompleted") === true;

  if (outcome !== "SETUP_FAILED_ROLLBACK_FAILED") {
    const title = outcome === "SETUP_CANCELLED_ROLLED_BACK" ? "Remote synchronization cancelled" : "Remote synchronization failed";
    return [
      `✗ ${title}`,
      "",
      "Failed stage",
      `  ${failedStage}`,
      "",
      "Recovery",
      "  ✓ Previous verified generation restored",
      "  ✓ Dispatcher verified",
      "  ✓ Authorization verified",
      "  ✓ Security boundary verified",
      "",
      "Current state",
      `  ${active} remains active.`,
      "",
      "Mutation",
      `  ${mutation ? "Remote mutation began and was rolled back." : "No remote mutation occurred."}`,
      "",
      "Next",
      "  opshaven doctor",
    ].join("\n");
  }

  const debugValue = safeScalar(detail(error, "rollbackDebug"), "no lower-level diagnostic was recorded");
  const lines = [
    "✗ Remote synchronization failed",
    "",
    "Failed stage",
    `  ${failedStage}`,
    "",
    "Recovery",
    `  ${rollbackStarted ? "✗ Previous generation could not be restored" : "✗ Rollback could not be started"}`,
    "",
    "Cause",
    "  The saved rollback evidence did not verify as the exact recorded previous generation.",
    "",
    "Current state",
    `  Active generation: ${active}`,
    `  Previous verified generation: ${previous}`,
    `  Remote mutation occurred: ${mutation ? "yes" : "no"}`,
    `  Rollback completed: ${rollbackCompleted ? "yes" : "no"}`,
    "  Deployment planning and apply are blocked.",
    "  Read-only verification is permitted only when boundary checks pass.",
    "",
    "Next",
    "  Inspect the recovery state:",
    "",
    "  opshaven doctor --debug",
    "",
    "  Then run the reviewed recovery flow:",
    "",
    "  opshaven setup repair",
  ];
  if (debug) lines.push("", "Debug", `  ${debugValue}`);
  return lines.join("\n");
}

export function formatOperatorError(error: unknown, args: readonly string[] = process.argv.slice(2)): string {
  const raw = error instanceof Error ? error.message : "The operation failed safely.";
  const debug = debugEnabled(args);
  if (error instanceof OpsHavenError) {
    const synchronization = synchronizationFailure(error, debug);
    if (synchronization) return synchronization;
  }
  if (debug) {
    if (error instanceof OpsHavenError) {
      const lower = detail(error, "rollbackDebug") ?? detail(error, "dispatcherDebug") ?? detail(error, "uninstallDebug");
      if (typeof lower === "string" && lower.length > 0) return `${sanitizeOperatorText(raw)}\n\nDebug\n  ${lower.replace(/[\r\n\u001b\u009b]/g, " ").slice(0, 500)}`;
    }
    return sanitizeOperatorText(raw);
  }

  if (/Unknown command/i.test(raw)) {
    return formatOperatorFailure({
      title: "Command not recognized",
      cause: raw,
      next: "Review the available operator commands.",
      run: "opshaven help",
    });
  }

  if (/Unknown boundary command/i.test(raw)) {
    return formatOperatorFailure({
      title: "Boundary command not recognized",
      cause: raw,
      next: "Use the supported boundary verification command.",
      run: "opshaven boundary verify",
    });
  }

  if (/Host identity was not accepted|First-time setup was cancelled/i.test(raw)) {
    return formatOperatorFailure({
      title: "Setup cancelled",
      cause: raw,
      checked: [{ label: "No incomplete setup state was created", state: "passed" }],
      next: "Run initialization again when you are ready to confirm the remote machine.",
      run: "opshaven init",
    });
  }

  if (/Host identity unavailable|SSH host-key fingerprint|provided SSH fingerprint|pinned known_hosts/i.test(raw)) {
    return formatOperatorFailure({
      title: "Host identity could not be verified",
      cause: raw,
      checked: [{ label: "SSH host identity", state: "failed" }],
      next: "Verify the server fingerprint independently and configure a pinned known_hosts entry.",
      run: "opshaven init",
    });
  }

  if (/Permission denied|publickey|SSH authentication|administrator SSH authentication/i.test(raw)) {
    return formatOperatorFailure({
      title: "Remote setup cannot continue",
      cause: "Administrator SSH authentication failed.",
      checked: [
        { label: "Host identity", state: "passed" },
        { label: "SSH authentication", state: "failed" },
      ],
      next: "Verify the administrator username and private key, then run the health check.",
      run: "opshaven doctor",
    });
  }

  if (/Setup is not initialized|Operator setup is not initialized|Remote deployment details are not configured/i.test(raw)) {
    return formatOperatorFailure({
      title: "OpsHaven is not initialized",
      cause: "Setup is not initialized. No complete operator setup was found.",
      checked: [{ label: "Local operator setup", state: "failed" }],
      next: "Complete the first-time setup wizard.",
      run: "opshaven init",
    });
  }

  if (/Remote setup configuration|setup configuration version|setup .* schema|setup .* malformed/i.test(raw)) {
    return formatOperatorFailure({
      title: "Operator setup needs repair",
      cause: "Setup state is missing or outdated. The saved operator setup could not be validated.",
      checked: [{ label: "Saved setup state", state: "failed" }],
      next: "Re-run initialization to rebuild a complete operator setup.",
      run: "opshaven init",
    });
  }

  if (/Remote setup preflight failed/i.test(raw)) {
    return formatOperatorFailure({
      title: "Remote setup cannot continue",
      cause: preflightCause(raw),
      checked: [{ label: "Remote installation prerequisites", state: "failed" }],
      next: "Use the health check to identify the blocked prerequisite.",
      run: "opshaven doctor",
    });
  }

  if (/Remote setup was not explicitly approved/i.test(raw)) {
    return formatOperatorFailure({
      title: "Remote setup was not approved",
      cause: "The installation confirmation was declined or unavailable.",
      checked: [{ label: "No remote changes were applied", state: "passed" }],
      next: "Review the target and run setup again when you are ready to approve it.",
      run: "opshaven setup remote",
    });
  }

  if (/capability|declaration binding|operator signing|authorization artifact|approval signing key/i.test(raw)) {
    return formatOperatorFailure({
      title: "Authorization setup is incomplete",
      cause: sanitizeOperatorText(raw),
      checked: [{ label: "Authorization state", state: "failed" }],
      next: "Run the health check before retrying the operation.",
      run: "opshaven doctor",
    });
  }

  if (error instanceof OpsHavenError && error.code === "CONFIG_INVALID") {
    return formatOperatorFailure({
      title: "Local operator setup is incomplete or outdated",
      cause: sanitizeOperatorText(raw),
      checked: [{ label: "Local operator setup", state: "failed" }],
      next: "Repair the setup through the guided initializer.",
      run: "opshaven init",
    });
  }

  return formatOperatorFailure({
    title: "Operation failed",
    cause: sanitizeOperatorText(raw),
    next: "Run the health check. Add --debug only when lower-level details are needed.",
    run: "opshaven doctor",
  });
}
