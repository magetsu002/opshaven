import { OPERATION_NAMES, type OperationName } from "../policy/operations.js";
import type { JsonValue } from "../security/canonical.js";

export type McpTool = Readonly<{
  name: OperationName;
  title: string;
  description: string;
  inputSchema: JsonValue;
  outputSchema: JsonValue;
  annotations: Readonly<{
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: false;
  }>;
  execution: Readonly<{ taskSupport: "forbidden" }>;
}>;

const ID = { type: "string", pattern: "^[a-z][a-z0-9_-]{1,63}$" } as const;
const COMMIT = { type: "string", pattern: "^[a-f0-9]{40}$" } as const;
const APPROVAL = {
  type: "object",
  additionalProperties: false,
  properties: {
    version: { const: 1 },
    digest: { type: "string", pattern: "^[a-f0-9]{64}$" },
    expiresAt: { type: "string", format: "date-time" },
    nonce: { type: "string", pattern: "^[A-Za-z0-9_-]{20,100}$" },
    mac: { type: "string", pattern: "^[A-Za-z0-9_-]{40,100}$" }
  },
  required: ["version", "digest", "expiresAt", "nonce", "mac"]
} as const;

const OUTPUT = {
  type: "object",
  oneOf: [
    {
      additionalProperties: false,
      properties: {
        ok: { const: true },
        operation: { type: "string" },
        requestId: { type: "string", format: "uuid" },
        hostId: { type: "string" },
        observedAt: { type: "string", format: "date-time" },
        data: {},
        truncated: { type: "boolean" }
      },
      required: ["ok", "operation", "requestId", "hostId", "observedAt", "data", "truncated"]
    },
    {
      additionalProperties: false,
      properties: {
        ok: { const: false },
        operation: { type: "string" },
        requestId: { type: "string", format: "uuid" },
        code: { type: "string" },
        message: { type: "string" },
        retryable: { type: "boolean" },
        details: { type: "object" }
      },
      required: ["ok", "operation", "requestId", "code", "message", "retryable", "details"]
    }
  ]
} as const;

function schema(properties: Record<string, JsonValue>, required: readonly string[]): JsonValue {
  return { type: "object", additionalProperties: false, properties, required };
}

const definitions: Readonly<Record<OperationName, Omit<McpTool, "name">>> = {
  get_host_summary: {
    title: "Get host summary",
    description: "Inspect bounded operating-system and capacity metadata for a configured host.",
    inputSchema: schema({ hostId: ID }, ["hostId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_deployed_commit: {
    title: "Get deployed commit",
    description: "Read the exact deployed Git commit for a configured deployment.",
    inputSchema: schema({ deploymentId: ID }, ["deploymentId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_service_status: {
    title: "Get service status",
    description: "Inspect bounded systemd status for a configured logical service.",
    inputSchema: schema({ serviceId: ID }, ["serviceId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_container_status: {
    title: "Get container status",
    description: "Inspect structured status for a configured container.",
    inputSchema: schema({ containerId: ID }, ["containerId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_runtime_config_status: {
    title: "Get runtime configuration status",
    description: "Report configured environment-key presence without returning environment values.",
    inputSchema: schema({ serviceId: ID }, ["serviceId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_reverse_proxy_summary: {
    title: "Get reverse proxy summary",
    description: "Inspect configured proxy routes and service state without reading raw proxy configuration.",
    inputSchema: schema({ proxyId: ID }, ["proxyId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_firewall_summary: {
    title: "Get firewall summary",
    description: "Inspect bounded firewall status and rule counts without returning raw rules.",
    inputSchema: schema({ hostId: ID }, ["hostId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  run_health_probe: {
    title: "Run health probe",
    description: "Run a configured local health probe and discard its response body.",
    inputSchema: schema({ probeId: ID }, ["probeId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_redacted_logs: {
    title: "Get redacted logs",
    description: "Read a bounded log window for a configured service with mandatory secret redaction.",
    inputSchema: schema(
      {
        serviceId: ID,
        lines: { type: "integer", minimum: 1, maximum: 500, default: 100 },
        window: { type: "string", enum: ["15m", "1h", "24h"], default: "1h" }
      },
      ["serviceId"]
    ),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_monitoring_status: {
    title: "Get monitoring status",
    description: "Inspect the configured monitoring service set.",
    inputSchema: schema({ monitoringId: ID }, ["monitoringId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_backup_status: {
    title: "Get backup status",
    description: "Inspect configured backup evidence freshness without reading backup contents.",
    inputSchema: schema({ backupId: ID }, ["backupId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  get_restore_readiness: {
    title: "Get restore readiness",
    description: "Report whether backup evidence and a restore procedure are present.",
    inputSchema: schema({ backupId: ID }, ["backupId"]),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  restart_service: {
    title: "Restart service",
    description: "Restart one configured service after exact, expiring, single-use human approval.",
    inputSchema: schema(
      {
        serviceId: ID,
        expectedActiveState: { type: "string", enum: ["active", "inactive", "failed"] },
        dryRun: { type: "boolean", default: false },
        approval: APPROVAL
      },
      ["serviceId", "expectedActiveState"]
    ),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  deploy_commit: {
    title: "Deploy commit",
    description: "Deploy one exact allowed Git commit transactionally after exact human approval.",
    inputSchema: schema(
      {
        deploymentId: ID,
        commit: COMMIT,
        expectedCurrentCommit: COMMIT,
        acknowledgeMigrationRisk: { type: "boolean", default: false },
        dryRun: { type: "boolean", default: false },
        approval: APPROVAL
      },
      ["deploymentId", "commit", "expectedCurrentCommit"]
    ),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  },
  rollback_deployment: {
    title: "Rollback deployment",
    description: "Activate one known recorded release after exact human approval; database migrations are never reversed.",
    inputSchema: schema(
      {
        deploymentId: ID,
        releaseCommit: COMMIT,
        expectedCurrentCommit: COMMIT,
        dryRun: { type: "boolean", default: false },
        approval: APPROVAL
      },
      ["deploymentId", "releaseCommit", "expectedCurrentCommit"]
    ),
    outputSchema: OUTPUT,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    execution: { taskSupport: "forbidden" }
  }
};

export const MCP_TOOLS: readonly McpTool[] = Object.freeze(
  OPERATION_NAMES.map((name) => Object.freeze({ name, ...definitions[name] }))
);

export function findMcpTool(name: string): McpTool | undefined {
  return MCP_TOOLS.find((tool) => tool.name === name);
}
