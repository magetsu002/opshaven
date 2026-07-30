import type { SecretRuleConfig } from "../config/schema.js";
import type { JsonValue } from "./canonical.js";

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9+/=_-]{6,}/gi;
const PEM = /-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----[\s\S]*?-----END [^-]*-----/g;
const URL_CREDENTIALS = /\b(https?:\/\/)([^\s/@:]+):([^\s/@]+)@/gi;
const URL_QUERY = /\b(https?:\/\/[^\s?#]+)\?[^\s#]*/gi;
const COOKIE = /\b(set-cookie|cookie)\s*:\s*[^\r\n]+/gi;
const AUTHORIZATION = /\bauthorization\s*:\s*[^\r\n]+/gi;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function redactText(text: string, rules: SecretRuleConfig): string {
  let output = text
    .replace(PEM, "[REDACTED_PRIVATE_KEY]")
    .replace(JWT, "[REDACTED_JWT]")
    .replace(BEARER, "$1 [REDACTED]")
    .replace(AUTHORIZATION, "authorization: [REDACTED]")
    .replace(COOKIE, "$1: [REDACTED]")
    .replace(URL_CREDENTIALS, "$1[REDACTED]@")
    .replace(URL_QUERY, "$1?[REDACTED]");

  for (const keyName of rules.keyNames) {
    if (keyName.length === 0) continue;
    const pattern = new RegExp(`\\b(${escapeRegExp(keyName)})\\s*([=:])\\s*([^\\s,;]+)`, "gi");
    output = output.replace(pattern, "$1$2[REDACTED]");
  }
  for (const fingerprint of rules.fingerprints) {
    if (fingerprint.length < 4) continue;
    output = output.split(fingerprint).join("[REDACTED_FINGERPRINT]");
  }
  return output;
}

export function redactJson(value: JsonValue, rules: SecretRuleConfig): JsonValue {
  if (typeof value === "string") return redactText(value, rules);
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (Array.isArray(value)) return value.map((item) => redactJson(item, rules));
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => {
      const secretKey = rules.keyNames.some((name) => key.toLowerCase().includes(name.toLowerCase()));
      return [key, secretKey ? "[REDACTED]" : redactJson(item, rules)];
    })
  );
}
