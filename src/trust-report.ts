import {
  capabilityDeclarationPath,
  compareCapabilityDeclarations,
  loadCapabilityDeclaration,
  loadVerifiedDeclarationBinding,
  type BuildCapabilityDeclaration,
  type CapabilityComparison,
  type DeclarationMode,
} from "./capability-declaration.js";
import type { OpsHavenConfig } from "./config.js";
import { loadClientProtocolContext } from "./remote/authenticated-protocol.js";
import { loadRemoteTrust, type RemoteTrustSummary } from "./remote-mcp/report.js";
import { formatBoundaryReport, verifyBoundary, type BoundaryReport } from "./boundary.js";

export interface TrustAccessReport {
  shellAccess: "denied";
  sudoAccess: "unavailable" | "exact-reviewed-commands";
  writeAccess: string[];
  dockerSocketAccess: "unavailable" | "configured-rootless-only";
}

export interface OperatorTrustReport {
  ok: boolean;
  generatedAt: string;
  activeMode: DeclarationMode;
  policyVersion: string;
  allowedOperations: string[];
  allowedResources: Record<string, string[]>;
  outputLimits: { timeoutMs: number; maxBytes: number; maxLines: number };
  access: TrustAccessReport;
  remoteMcp: RemoteTrustSummary;
  capabilitySignatureStatus: "valid";
  declarationSignatureStatus: "valid";
  dispatcherArtifactStatus: "valid";
  capabilityHash: string;
  dispatcherSha256: string;
  declarationSha256: string;
  boundaryVerification: BoundaryReport;
  capabilityChanges: CapabilityComparison | null;
  enforcedBoundary: string;
  remainingAssumptions: string[];
}

export function summarizeDeclaredAccess(declaration: BuildCapabilityDeclaration, mode: DeclarationMode): TrustAccessReport {
  const active = declaration.modes[mode];
  return {
    shellAccess: "denied",
    sudoAccess: active.sudoRequirements.length > 0 ? "exact-reviewed-commands" : "unavailable",
    writeAccess: [...active.filesystemWrite],
    dockerSocketAccess: active.executables.includes("docker") ? "configured-rootless-only" : "unavailable",
  };
}

export async function buildTrustReport(
  config: OpsHavenConfig,
  configPath: string,
  dispatcherPath: string,
  mode: DeclarationMode = "controlled",
  previousDeclarationPath?: string,
): Promise<OperatorTrustReport> {
  const protocol = await loadClientProtocolContext(config, configPath, mode);
  const declaration = await loadCapabilityDeclaration(capabilityDeclarationPath(configPath));
  const declarationBinding = await loadVerifiedDeclarationBinding(config, configPath, mode, dispatcherPath);
  const boundary = await verifyBoundary(config, configPath, mode);
  const remote = await loadRemoteTrust(configPath, config);
  const boundaryVerification: BoundaryReport = {
    ok: boundary.ok && remote.assertions.every((item) => item.passed),
    checkedAt: boundary.checkedAt,
    assertions: [...boundary.assertions, ...remote.assertions],
  };
  const capabilityChanges = previousDeclarationPath
    ? compareCapabilityDeclarations(await loadCapabilityDeclaration(previousDeclarationPath), declaration)
    : null;
  const access = summarizeDeclaredAccess(declaration, mode);
  return {
    ok: boundaryVerification.ok,
    generatedAt: new Date().toISOString(),
    activeMode: mode,
    policyVersion: config.policyVersion,
    allowedOperations: [...protocol.capability.payload.allowedOperations],
    allowedResources: Object.fromEntries(Object.entries(protocol.capability.payload.allowedResources).map(([operation, resources]) => [operation, [...resources]])),
    outputLimits: { ...protocol.capability.payload.limits },
    access,
    remoteMcp: remote.summary,
    capabilitySignatureStatus: "valid",
    declarationSignatureStatus: "valid",
    dispatcherArtifactStatus: "valid",
    capabilityHash: protocol.capability.hash,
    dispatcherSha256: protocol.capability.payload.dispatcherSha256,
    declarationSha256: declarationBinding.payload.declarationSha256,
    boundaryVerification,
    capabilityChanges,
    enforcedBoundary: "The restricted SSH key can invoke only the forced dispatcher. Remote MCP remains disabled unless a reviewed localhost listener, OIDC verification, exact origin and host policy, signed read-only capability authorization, and operator-owned profile mapping all validate.",
    remainingAssumptions: [
      "The VPS kernel, OpenSSH, Node.js runtime, systemd, fixed executables, and operator signing keys remain correctly controlled.",
      "Configured root ownership, sudo rules, rootless Docker setup, health probes, backups, and logical resource mappings remain correct.",
      "The configured OAuth issuer, reviewed reverse proxy or HTTPS tunnel, DNS, and token revocation policy remain correctly controlled when remote MCP is enabled.",
      "A valid report records boundary verification at the reported time; it is not a claim of absolute security or vulnerability absence.",
    ],
  };
}

export function formatTrustReport(report: OperatorTrustReport): string {
  const lines = [
    `OpsHaven authorization report: ${report.ok ? "BOUNDARY VERIFIED" : "BOUNDARY FAILED"}`,
    `Active mode: ${report.activeMode}`,
    `Policy version: ${report.policyVersion}`,
    `Capability authorization: ${report.capabilitySignatureStatus}`,
    `Signed policy declaration: ${report.declarationSignatureStatus}`,
    `Deployment attestation: ${report.dispatcherArtifactStatus}`,
    `Shell access: ${report.access.shellAccess}`,
    `Sudo access: ${report.access.sudoAccess}`,
    `Write access: ${report.access.writeAccess.length ? report.access.writeAccess.join(", ") : "unavailable"}`,
    `Docker socket access: ${report.access.dockerSocketAccess}`,
    `Allowed operations: ${report.allowedOperations.join(", ")}`,
    `Remote MCP exposure: ${report.remoteMcp.enabled ? "enabled" : "disabled"}`,
    `Endpoint authentication: ${report.remoteMcp.authentication}`,
    `Remote capability: ${report.remoteMcp.readOnly ? "read-only" : "contains mutation authority"}`,
  ];
  if (report.remoteMcp.bindAddress) lines.push(`Endpoint bind: ${report.remoteMcp.bindAddress}${report.remoteMcp.path ?? ""}`);
  if (report.remoteMcp.trustedProxies.length) lines.push(`Reviewed proxy addresses: ${report.remoteMcp.trustedProxies.join(", ")}`);
  for (const [operation, resources] of Object.entries(report.allowedResources)) lines.push(`  ${operation}: ${resources.join(", ")}`);
  for (const [profile, tools] of Object.entries(report.remoteMcp.effectiveTools)) lines.push(`  endpoint.${profile}: ${tools.join(", ")}`);
  lines.push("", formatBoundaryReport(report.boundaryVerification).trim());
  if (report.capabilityChanges) {
    lines.push("", `Capability authorization changes: ${report.capabilityChanges.authorityExpanded ? "authority expansion detected" : "no authority expansion"}`);
    for (const mode of ["controlled", "read-only"] as const) {
      for (const change of report.capabilityChanges.modes[mode]) {
        for (const item of change.added) lines.push(`  + ${mode}.${change.field}: ${item}`);
        for (const item of change.removed) lines.push(`  - ${mode}.${change.field}: ${item}`);
      }
    }
  }
  lines.push("", "Enforced boundary:", report.enforcedBoundary, "", "Remaining platform assumptions:");
  for (const assumption of report.remainingAssumptions) lines.push(`- ${assumption}`);
  return `${lines.join("\n")}\n`;
}
