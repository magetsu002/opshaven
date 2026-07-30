import { createHash } from "node:crypto";
import { OpsHavenError } from "./errors.js";

export interface OutputLimits { maxBytes: number; maxLines: number }
export interface RedactionResult { text: string; redactions: number; truncated: boolean; lineCount: number; byteCount: number }

const RULES: readonly RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /\b(?:Basic)\s+[A-Za-z0-9+/]+=*/gi,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(?:authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|secret|password|passwd|client_secret)\s*[:=]\s*[^\s,;]+/gi,
  /\b(?:https?|postgres(?:ql)?|mysql|redis):\/\/[^\s/@:]+:[^\s/@]+@[^\s]+/gi,
  /([?&](?:token|key|secret|password|signature|sig)=)[^&#\s]+/gi,
  /\b(?:https?|postgres(?:ql)?|mysql|redis):\/\/[^\s"'<>]+/gi,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
];

export function fingerprintSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

function printableRatio(value: string): number {
  if (value.length === 0) return 1;
  let printable = 0;
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (char === "\n" || char === "\r" || char === "\t" || (code >= 32 && code <= 126) || code >= 160) printable += 1;
  }
  return printable / value.length;
}

export function sanitizeOutput(input: string | Uint8Array, limits: OutputLimits, configuredFingerprints: readonly string[] = []): RedactionResult {
  const raw = typeof input === "string" ? input : Buffer.from(input).toString("utf8");
  if (raw.includes("\u0000") || printableRatio(raw) < 0.85) throw new OpsHavenError("BINARY_OUTPUT", "Binary or non-text output was rejected.");
  let text = raw;
  let redactions = 0;
  for (const rule of RULES) {
    text = text.replace(rule, (match, prefix?: string) => {
      redactions += 1;
      return typeof prefix === "string" && prefix.length > 0 ? `${prefix}[REDACTED]` : "[REDACTED]";
    });
  }
  const lines = text.split(/\r?\n/);
  const safeLines: string[] = [];
  let bytes = 0;
  let truncated = false;
  for (const line of lines) {
    let safeLine = line;
    for (const fingerprint of configuredFingerprints) {
      if (fingerprint.length < 8) continue;
      const tokens = safeLine.split(/([^A-Za-z0-9_./+=-]+)/);
      safeLine = tokens.map((token) => {
        if (fingerprintSecret(token) !== fingerprint.toLowerCase()) return token;
        redactions += 1;
        return "[REDACTED]";
      }).join("");
    }
    const next = `${safeLine}\n`;
    const nextBytes = Buffer.byteLength(next, "utf8");
    if (safeLines.length >= limits.maxLines || bytes + nextBytes > limits.maxBytes) {
      truncated = true;
      break;
    }
    safeLines.push(safeLine);
    bytes += nextBytes;
  }
  return { text: safeLines.join("\n"), redactions, truncated, lineCount: safeLines.length, byteCount: bytes };
}
