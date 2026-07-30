import { createHash } from "node:crypto";
import { OpsHavenError } from "./errors.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export function canonicalize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new OpsHavenError("INVALID_ARGUMENTS", "Non-finite numbers are not allowed.");
    return value;
  }
  if (Array.isArray(value)) return value.map(sortValue);
  if (typeof value === "object") {
    const output: Record<string, JsonValue> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item !== undefined) output[key] = sortValue(item);
    }
    return output;
  }
  throw new OpsHavenError("INVALID_ARGUMENTS", "Unsupported value type.");
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalize(value)).digest("hex");
}

export function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new OpsHavenError("CONFIG_INVALID", `${label} must be an object.`);
  }
}

export function rejectUnknownKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !allowedSet.has(key));
  if (unknown.length) throw new OpsHavenError("CONFIG_INVALID", `${label} contains unknown fields.`, false, { fields: unknown.sort() });
}
