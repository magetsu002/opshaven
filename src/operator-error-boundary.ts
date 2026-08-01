import { createHash } from "node:crypto";
import { OpsHavenError } from "./errors.js";
import { formatOperatorError as formatLegacyOperatorError } from "./operator-errors.js";

function debugEnabled(args: readonly string[]): boolean {
  return args.includes("--debug") || process.argv.includes("--debug") || process.env.OPSHAVEN_DEBUG === "1";
}

function reference(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}

function scrubLine(line: string): string | null {
  if (/^Traceback \(most recent call last\):/i.test(line.trim())) return null;
  if (/^File ["'].*["'], line \d+/i.test(line.trim())) return null;
  if (/^(?:RuntimeError|ValueError|KeyError|TypeError|OSError|Exception|Error):/i.test(line.trim())) return null;
  const withoutPaths = line
    .replace(/(?:\/[A-Za-z0-9._@+-]+){2,}/g, "<protected path>")
    .replace(/\b(?:RuntimeError|ValueError|KeyError|TypeError|OSError|Exception)\b:?/g, "internal failure")
    .replace(/[\u001b\u009b]/g, "");
  return withoutPaths.slice(0, 1000);
}

export function sanitizeOperatorFailureOutput(value: string): string {
  return value
    .replace(/\r/g, "")
    .split("\n")
    .map(scrubLine)
    .filter((line): line is string => line !== null)
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function safeDetail(error: OpsHavenError, key: string): string | null {
  const value = error.safeDetails?.[key];
  return typeof value === "string" && value.length > 0 ? sanitizeOperatorFailureOutput(value).slice(0, 240) : null;
}

function partialGenerationFailure(error: unknown, args: readonly string[]): string | null {
  const raw = error instanceof Error ? error.message : "";
  const currentState = error instanceof OpsHavenError ? safeDetail(error, "currentKnownState") : null;
  const partial = currentState === "REMOTE_GENERATION_PARTIAL"
    || /previous generation identity is partial|generation evidence is partial|incomplete identity evidence/i.test(raw);
  if (!partial) return null;
  const lines = [
    "✗ Remote synchronization blocked",
    "",
    "Failed stage",
    "  Previous-generation identity verification",
    "",
    "Cause",
    "  The installed previous generation has incomplete identity evidence.",
    "",
    "Changes",
    "  No remote activation occurred.",
    "",
    "Rollback",
    "  Not required because synchronization did not begin.",
    "",
    "Current state",
    "  The existing installation cannot be trusted for deployment updates.",
    "  Deployment planning, apply, and boundary certification are blocked.",
    "",
    "Next",
    "  Run the reviewed repair flow:",
    "",
    "  opshaven setup repair",
    "",
    "Debug reference",
    `  ${reference(raw || "partial-generation")}`,
  ];
  if (debugEnabled(args)) {
    lines.push("", "Debug", "  Classification: REMOTE_GENERATION_PARTIAL", "  Mutation status: not started");
  }
  return lines.join("\n");
}

export function formatOperatorError(error: unknown, args: readonly string[] = process.argv.slice(2)): string {
  const partial = partialGenerationFailure(error, args);
  if (partial) return partial;
  const raw = error instanceof Error ? error.message : "The operation failed safely.";
  const formatted = sanitizeOperatorFailureOutput(formatLegacyOperatorError(error, args));
  if (formatted.length > 0) return formatted;
  return [
    "✗ Operation failed",
    "",
    "Cause",
    "  The operation failed at a protected internal boundary.",
    "",
    "Changes",
    "  Mutation status could not be confirmed from the returned evidence.",
    "",
    "Next",
    "  opshaven doctor",
    "",
    "Debug reference",
    `  ${reference(raw)}`,
  ].join("\n");
}
