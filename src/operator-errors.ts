import { OpsHavenError } from "./errors.js";

function debugEnabled(args: readonly string[]): boolean {
  return args.includes("--debug") || process.argv.includes("--debug") || process.env.OPSHAVEN_DEBUG === "1";
}

function startup(message: string, action: string): string {
  return `Startup blocked.\n\n${message}\n\nRun:\n${action}`;
}

export function formatOperatorError(error: unknown, args: readonly string[] = process.argv.slice(2)): string {
  const raw = error instanceof Error ? error.message : "The operation failed safely.";
  if (debugEnabled(args)) return `INIT_DIAGNOSTIC:${Buffer.from(raw, "utf8").toString("base64")}`;

  if (/Setup is not initialized|Remote deployment details are not configured/i.test(raw)) {
    return startup("Setup is not initialized.", "opshaven init");
  }

  if (/Remote setup configuration|setup configuration version|setup .* schema|setup .* malformed/i.test(raw)) {
    return startup("Setup state is missing or outdated.", "opshaven init");
  }

  if (/capability|declaration binding|operator signing|authorization artifact|approval signing key/i.test(raw)) {
    return startup("Authorization setup is incomplete.", "opshaven init");
  }

  if (/Remote setup preflight failed/i.test(raw)) {
    return startup("Remote deployment prerequisites are incomplete.", "opshaven doctor");
  }

  if (error instanceof OpsHavenError && error.code === "CONFIG_INVALID") {
    return startup("Local operator setup is incomplete or outdated.", "opshaven init");
  }

  return raw;
}
