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

export function formatOperatorError(error: unknown, args: readonly string[] = process.argv.slice(2)): string {
  const raw = error instanceof Error ? error.message : "The operation failed safely.";
  if (debugEnabled(args)) return raw;

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
