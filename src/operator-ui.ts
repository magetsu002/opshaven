export type UiTone = "success" | "warning" | "failure" | "info" | "muted";
export type UiState = "passed" | "warning" | "failed" | "pending" | "skipped" | "rolled-back";

interface StreamLike {
  readonly isTTY?: boolean;
  readonly write?: unknown;
}

type Environment = Readonly<Record<string, string | undefined>>;

const ANSI = Object.freeze({
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  green: "\u001b[32m",
  yellow: "\u001b[33m",
  red: "\u001b[31m",
  blue: "\u001b[34m",
  gray: "\u001b[90m",
});

const TONE_CODE: Readonly<Record<UiTone, string>> = Object.freeze({
  success: ANSI.green,
  warning: ANSI.yellow,
  failure: ANSI.red,
  info: ANSI.blue,
  muted: ANSI.gray,
});

const STATE_TONE: Readonly<Record<UiState, UiTone>> = Object.freeze({
  passed: "success",
  warning: "warning",
  failed: "failure",
  pending: "warning",
  skipped: "muted",
  "rolled-back": "warning",
});

const STATE_SYMBOL: Readonly<Record<UiState, string>> = Object.freeze({
  passed: "✓",
  warning: "!",
  failed: "✗",
  pending: "⏳",
  skipped: "○",
  "rolled-back": "↶",
});

export interface FailureCheck {
  readonly label: string;
  readonly state: "passed" | "failed" | "warning";
}

export interface OperatorFailure {
  readonly title: string;
  readonly cause: string;
  readonly checked?: readonly FailureCheck[];
  readonly next: string;
  readonly run?: string;
}

export function colorEnabled(
  env: Environment = process.env,
  stream: StreamLike = process.stdout as StreamLike,
): boolean {
  if (Object.prototype.hasOwnProperty.call(env, "NO_COLOR")) return false;
  if (env.OPSHAVEN_COLOR === "never" || env.TERM === "dumb") return false;
  if (env.OPSHAVEN_COLOR === "always" || env.FORCE_COLOR === "1" || env.FORCE_COLOR === "true") return true;
  return stream.isTTY === true;
}

export function paint(text: string, tone: UiTone, enabled = colorEnabled()): string {
  return enabled ? `${TONE_CODE[tone]}${text}${ANSI.reset}` : text;
}

export function strong(text: string, enabled = colorEnabled()): string {
  return enabled ? `${ANSI.bold}${text}${ANSI.reset}` : text;
}

export function heading(title: string, enabled = colorEnabled()): string {
  return strong(title, enabled);
}

export function section(title: string, enabled = colorEnabled()): string {
  return paint(title, "info", enabled);
}

export function statusLine(state: UiState, label: string, detail?: string, enabled = colorEnabled()): string {
  const symbol = paint(STATE_SYMBOL[state], STATE_TONE[state], enabled);
  return `${symbol} ${label}${detail ? ` — ${detail}` : ""}`;
}

export function numberedStatus(
  index: number,
  total: number,
  state: UiState,
  label: string,
  detail?: string,
  enabled = colorEnabled(),
): string {
  return `[${index}/${total}] ${statusLine(state, label, detail, enabled)}`;
}

export function command(value: string, enabled = colorEnabled()): string {
  return `  ${paint(value, "info", enabled)}`;
}

export function sanitizeOperatorText(value: string): string {
  return value
    .replace(/\/[A-Za-z0-9._/-]+/g, "<protected path>")
    .replace(/declaration binding/gi, "deployment verification")
    .replace(/capability artifacts?/gi, "authorization data")
    .replace(/capability authorization/gi, "authorization")
    .replace(/dispatcher/gi, "remote runtime")
    .replace(/trust material/gi, "authorization data")
    .trim();
}

export function formatOperatorFailure(value: OperatorFailure, enabled = colorEnabled(process.env, process.stderr as StreamLike)): string {
  const lines = [
    "Startup blocked.",
    "",
    `${paint("✗", "failure", enabled)} ${strong(value.title, enabled)}`,
    "",
    section("Cause:", enabled),
    sanitizeOperatorText(value.cause),
  ];
  if (value.checked?.length) {
    lines.push("", section("Checked:", enabled));
    for (const item of value.checked) lines.push(statusLine(item.state, item.label, undefined, enabled));
  }
  lines.push("", section("Next:", enabled), value.next);
  if (value.run) lines.push("", section("Run:", enabled), command(value.run, enabled));
  return lines.join("\n");
}
