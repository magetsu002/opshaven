import assert from "node:assert/strict";
import test from "node:test";
import type { BuildCapabilityDeclaration } from "../src/capability-declaration.js";
import { formatTrustReport, summarizeDeclaredAccess, type OperatorTrustReport } from "../src/trust-report.js";

const declaration: BuildCapabilityDeclaration = {
  version: 1,
  build: "fixture",
  modes: {
    controlled: {
      operations: ["get_host_summary", "restart_service"],
      remoteHandlers: ["inspection", "mutation"],
      filesystemRead: ["root-owned trust files"],
      filesystemWrite: ["approval replay state"],
      executables: ["sudo", "systemctl"],
      networkAccess: ["restricted SSH stdio"],
      sudoRequirements: ["exact configured systemctl restart commands"],
      outputFields: ["structured status summaries"],
    },
    "read-only": {
      operations: ["get_host_summary"],
      remoteHandlers: ["inspection"],
      filesystemRead: ["root-owned trust files"],
      filesystemWrite: ["request replay state"],
      executables: ["uname"],
      networkAccess: ["restricted SSH stdio"],
      sudoRequirements: [],
      outputFields: ["structured status summaries"],
    },
  },
};

test("trust report derives access only from the signed build declaration", () => {
  assert.deepEqual(summarizeDeclaredAccess(declaration, "controlled"), { shellAccess: "denied", sudoAccess: "exact-reviewed-commands", writeAccess: ["approval replay state"], dockerSocketAccess: "unavailable" });
  assert.deepEqual(summarizeDeclaredAccess(declaration, "read-only"), { shellAccess: "denied", sudoAccess: "unavailable", writeAccess: ["request replay state"], dockerSocketAccess: "unavailable" });
});

test("plain trust report states remote posture, enforced boundary, and remaining assumptions", () => {
  const report: OperatorTrustReport = {
    ok: true,
    generatedAt: "2026-07-30T20:00:00.000Z",
    activeMode: "controlled",
    policyVersion: "v1",
    allowedOperations: ["get_host_summary"],
    allowedResources: { get_host_summary: ["host.main"] },
    outputLimits: { timeoutMs: 5000, maxBytes: 65536, maxLines: 500 },
    access: summarizeDeclaredAccess(declaration, "controlled"),
    remoteMcp: { enabled: true, bindAddress: "127.0.0.1:43110", path: "/mcp", authentication: "oidc-bearer", allowedOrigins: ["https://chat.example.test"], allowedHosts: ["mcp.example.test"], trustedProxies: [], effectiveTools: { readonly: ["get_host_summary"] }, readOnly: true },
    capabilitySignatureStatus: "valid",
    declarationSignatureStatus: "valid",
    dispatcherArtifactStatus: "valid",
    capabilityHash: "a".repeat(64),
    dispatcherSha256: "b".repeat(64),
    declarationSha256: "c".repeat(64),
    boundaryVerification: { ok: true, checkedAt: "2026-07-30T20:00:00.000Z", assertions: [{ name: "interactive shell denied", passed: true, detail: "forced-command policy denial" }] },
    capabilityChanges: null,
    enforcedBoundary: "Only signed, bounded requests reach the forced dispatcher.",
    remainingAssumptions: ["The operator keys and VPS kernel remain trustworthy.", "This is not a claim of absolute security."],
  };
  const text = formatTrustReport(report);
  assert.match(text, /BOUNDARY VERIFIED/);
  assert.match(text, /Shell access: denied/);
  assert.match(text, /Sudo access: exact-reviewed-commands/);
  assert.match(text, /Capability signature: valid/);
  assert.match(text, /Dispatcher artifact: valid/);
  assert.match(text, /Remote MCP: enabled/);
  assert.match(text, /Remote authentication: oidc-bearer/);
  assert.match(text, /Remote read-only: yes/);
  assert.match(text, /Remaining assumptions:/);
  assert.match(text, /not a claim of absolute security/i);
});
