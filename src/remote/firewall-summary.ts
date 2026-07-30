import { sanitizeOutput, type OutputLimits } from "../redaction.js";

export interface FirewallSummary {
  [key: string]: unknown;
  provider: "ufw";
  status: "active" | "inactive" | "unknown";
  logging: "on" | "off" | "unknown";
  defaults: {
    incoming: "allow" | "deny" | "reject" | "unknown";
    outgoing: "allow" | "deny" | "reject" | "unknown";
    routed: "allow" | "deny" | "reject" | "disabled" | "unknown";
  };
  rules: {
    total: number;
    ipv4: number;
    ipv6: number;
    allow: number;
    deny: number;
    reject: number;
    limit: number;
  };
  parsedLines: number;
  ignoredLines: number;
  redactions: number;
  truncated: boolean;
}

function policy(value: string | undefined): FirewallSummary["defaults"]["incoming"] {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "allow" || normalized === "deny" || normalized === "reject") return normalized;
  return "unknown";
}

function routedPolicy(value: string | undefined): FirewallSummary["defaults"]["routed"] {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "disabled") return "disabled";
  return policy(value);
}

export function parseUfwSummary(
  input: string | Uint8Array,
  limits: OutputLimits,
  secretFingerprints: readonly string[] = [],
): FirewallSummary {
  const safe = sanitizeOutput(input, limits, secretFingerprints);
  let status: FirewallSummary["status"] = "unknown";
  let logging: FirewallSummary["logging"] = "unknown";
  const defaults: FirewallSummary["defaults"] = { incoming: "unknown", outgoing: "unknown", routed: "unknown" };
  const rules: FirewallSummary["rules"] = { total: 0, ipv4: 0, ipv6: 0, allow: 0, deny: 0, reject: 0, limit: 0 };
  let parsedLines = 0;
  let ignoredLines = 0;

  for (const rawLine of safe.text.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const statusMatch = /^Status:\s*(active|inactive)$/i.exec(line);
    if (statusMatch?.[1]) {
      status = statusMatch[1].toLowerCase() as FirewallSummary["status"];
      parsedLines += 1;
      continue;
    }
    const loggingMatch = /^Logging:\s*(on|off)\b/i.exec(line);
    if (loggingMatch?.[1]) {
      logging = loggingMatch[1].toLowerCase() as FirewallSummary["logging"];
      parsedLines += 1;
      continue;
    }
    const defaultMatch = /^Default:\s*([a-z]+)\s*\(incoming\),\s*([a-z]+)\s*\(outgoing\),\s*([a-z]+)\s*\(routed\)$/i.exec(line);
    if (defaultMatch) {
      defaults.incoming = policy(defaultMatch[1]);
      defaults.outgoing = policy(defaultMatch[2]);
      defaults.routed = routedPolicy(defaultMatch[3]);
      parsedLines += 1;
      continue;
    }
    const actionMatch = /\b(ALLOW|DENY|REJECT|LIMIT)(?:\s+(?:IN|OUT))?\b/i.exec(line);
    if (actionMatch?.[1] && (/^\[\s*\d+\]/.test(line) || /\s{2,}/.test(line))) {
      const action = actionMatch[1].toLowerCase() as "allow" | "deny" | "reject" | "limit";
      rules.total += 1;
      rules[action] += 1;
      if (/\(v6\)/i.test(line)) rules.ipv6 += 1;
      else rules.ipv4 += 1;
      parsedLines += 1;
      continue;
    }
    ignoredLines += 1;
  }

  return { provider: "ufw", status, logging, defaults, rules, parsedLines, ignoredLines, redactions: safe.redactions, truncated: safe.truncated };
}
