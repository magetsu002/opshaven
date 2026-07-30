import { promises as fs } from "node:fs";
import path from "node:path";
import { capabilityManifestPath } from "../capabilities.js";
import type { OpsHavenConfig } from "../config.js";
import { OpsHavenError } from "../errors.js";
import { responsePrivateKeyPath } from "./authenticated-protocol.js";

interface ProtectedPathOptions {
  directory?: boolean;
  expectedUid: number;
  allowedMode: number;
  executable?: boolean;
}

async function assertProtectedPath(filePath: string, label: string, options: ProtectedPathOptions): Promise<void> {
  if (!path.isAbsolute(filePath) || path.normalize(filePath) !== filePath || filePath.includes("..")) {
    throw new OpsHavenError("POLICY_DENIED", `${label} path is unsafe.`);
  }
  const stat = await fs.lstat(filePath).catch(() => null);
  if (!stat || stat.isSymbolicLink() || (options.directory ? !stat.isDirectory() : !stat.isFile())) {
    throw new OpsHavenError("POLICY_DENIED", `${label} must be a real ${options.directory ? "directory" : "regular file"}.`);
  }
  const real = await fs.realpath(filePath);
  if (real !== filePath) throw new OpsHavenError("POLICY_DENIED", `${label} path substitution was detected.`);
  if (stat.uid !== options.expectedUid) throw new OpsHavenError("POLICY_DENIED", `${label} has an unexpected owner.`);
  if ((stat.mode & 0o777) & ~options.allowedMode) throw new OpsHavenError("POLICY_DENIED", `${label} permissions are too broad.`);
  if (options.executable && (stat.mode & 0o111) === 0) throw new OpsHavenError("POLICY_DENIED", `${label} is not executable.`);
  if ((stat.mode & 0o022) !== 0) throw new OpsHavenError("POLICY_DENIED", `${label} must not be group or world writable.`);
}

async function assertParentChain(filePath: string, expectedUid: number): Promise<void> {
  let current = path.dirname(filePath);
  while (current !== "/") {
    const stat = await fs.lstat(current).catch(() => null);
    if (!stat || !stat.isDirectory() || stat.isSymbolicLink()) {
      throw new OpsHavenError("POLICY_DENIED", "Protected path parent substitution was detected.");
    }
    if ((stat.mode & 0o002) !== 0) throw new OpsHavenError("POLICY_DENIED", "Protected path parent is world writable.");
    if (stat.uid !== 0 && stat.uid !== expectedUid) throw new OpsHavenError("POLICY_DENIED", "Protected path parent has an unexpected owner.");
    current = path.dirname(current);
  }
}

export async function assertRemoteConfinement(
  config: OpsHavenConfig,
  configPath: string,
  dispatcherPath: string,
  mode: "read-only" | "controlled",
  expectedRootUid = 0,
  runtimeUid = process.getuid?.() ?? expectedRootUid,
): Promise<{ privateTmp: string; noDockerSocket: boolean; noNewPrivilegesRequired: boolean }> {
  await assertProtectedPath(configPath, "Remote configuration", { expectedUid: expectedRootUid, allowedMode: 0o644 });
  await assertProtectedPath(capabilityManifestPath(configPath), "Capability manifest", { expectedUid: expectedRootUid, allowedMode: 0o644 });
  await assertProtectedPath(config.approvals.verificationPublicKeyFile, "Operator public key", { expectedUid: expectedRootUid, allowedMode: 0o644 });
  await assertProtectedPath(responsePrivateKeyPath(configPath), "Response signing key", { expectedUid: expectedRootUid, allowedMode: 0o640 });
  await assertProtectedPath(dispatcherPath, "Dispatcher artifact", { expectedUid: expectedRootUid, allowedMode: 0o755, executable: true });
  for (const protectedPath of [configPath, capabilityManifestPath(configPath), config.approvals.verificationPublicKeyFile, responsePrivateKeyPath(configPath), dispatcherPath]) {
    await assertParentChain(protectedPath, runtimeUid);
  }
  await assertProtectedPath(config.approvals.remoteUsedDirectory, "Remote state directory", { directory: true, expectedUid: runtimeUid, allowedMode: 0o700 });
  const privateTmp = path.join(config.approvals.remoteUsedDirectory, "tmp");
  await fs.mkdir(privateTmp, { recursive: true, mode: 0o700 });
  await fs.chmod(privateTmp, 0o700);
  await assertProtectedPath(privateTmp, "Private temporary directory", { directory: true, expectedUid: runtimeUid, allowedMode: 0o700 });
  process.umask(0o077);
  process.env.TMPDIR = privateTmp;
  process.env.TMP = privateTmp;
  process.env.TEMP = privateTmp;
  const dockerSocket = await fs.lstat("/var/run/docker.sock").catch(() => null);
  if (mode === "read-only" && dockerSocket) throw new OpsHavenError("POLICY_DENIED", "Read-only dispatcher must not have Docker socket access.");
  return { privateTmp, noDockerSocket: !dockerSocket, noNewPrivilegesRequired: mode === "read-only" };
}
