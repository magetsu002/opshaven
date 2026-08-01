import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { OpsHavenError } from "./errors.js";
import { detectKnownHostFingerprint, runInit } from "./operator-state.js";
import { colorEnabled, heading, paint, section, statusLine } from "./operator-ui.js";

const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{20,60}$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;

export interface SshAddress {
  readonly host: string;
  readonly port: number;
}

export interface FirstRunWizardDependencies {
  readonly interactive: boolean;
  ask(question: string, fallback?: string): Promise<string>;
  write(value: string): void;
  initialize(args: readonly string[]): Promise<void>;
}

function value(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}

function absolute(value: string): string {
  const home = homedir();
  const expanded = value === "~" ? home : value.startsWith("~/") ? path.join(home, value.slice(2)) : value;
  if (!path.isAbsolute(expanded) || path.normalize(expanded) !== expanded || expanded.includes("..")) {
    throw new OpsHavenError("CONFIG_INVALID", "The selected SSH file path must be an absolute normalized path.");
  }
  return expanded;
}

async function regularFile(filePath: string, ownerOnly: boolean): Promise<boolean> {
  try {
    const stat = await fs.lstat(filePath);
    return stat.isFile() && !stat.isSymbolicLink() && (!ownerOnly || (stat.mode & 0o077) === 0);
  } catch {
    return false;
  }
}

function port(value: string | undefined): number {
  const parsed = value === undefined ? 22 : Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new OpsHavenError("CONFIG_INVALID", "The SSH port must be a number from 1 to 65535.");
  }
  return parsed;
}

export function parseSshAddress(input: string): SshAddress {
  const selected = input.trim();
  const bracketed = /^\[([^\]]+)](?::(\d+))?$/.exec(selected);
  if (bracketed) return { host: bracketed[1] ?? "", port: port(bracketed[2]) };
  const separators = [...selected].filter((character) => character === ":").length;
  if (separators === 1) {
    const separator = selected.lastIndexOf(":");
    const host = selected.slice(0, separator);
    const selectedPort = selected.slice(separator + 1);
    if (/^\d+$/.test(selectedPort)) return { host, port: port(selectedPort) };
  }
  if (!selected) throw new OpsHavenError("CONFIG_INVALID", "An SSH address is required.");
  return { host: selected, port: 22 };
}

export function confirmationAccepted(answer: string, defaultYes: boolean): boolean {
  const normalized = answer.trim().toLowerCase();
  if (!normalized) return defaultYes;
  return normalized === "y" || normalized === "yes";
}

function selectedAddress(args: readonly string[]): string | undefined {
  const host = value(args, "--host");
  if (!host) return undefined;
  const selectedPort = port(value(args, "--port"));
  return host.includes(":") && !host.startsWith("[")
    ? `[${host}]:${selectedPort}`
    : `${host}:${selectedPort}`;
}

function initArguments(
  args: readonly string[],
  address: SshAddress,
  adminUser: string,
  adminIdentity: string,
  knownHosts: string,
  fingerprint: string,
): string[] {
  const result = [
    "--non-interactive",
    "--host", address.host,
    "--port", String(address.port),
    "--admin-user", adminUser,
    "--admin-identity", adminIdentity,
    "--known-hosts", knownHosts,
    "--host-key-sha256", fingerprint,
    "--privilege", value(args, "--privilege") ?? (adminUser === "root" ? "root" : "sudo-noninteractive"),
  ];
  const sourceSha = value(args, "--source-sha");
  if (sourceSha) result.push("--source-sha", sourceSha);
  if (args.includes("--json")) result.push("--json");
  return result;
}

export async function executeFirstRunWizard(args: readonly string[], dependencies: FirstRunWizardDependencies): Promise<void> {
  if (!dependencies.interactive || args.includes("--non-interactive") || args.includes("--local-only")) {
    await dependencies.initialize(args);
    return;
  }

  const color = colorEnabled();
  const home = homedir();
  const defaultIdentity = path.join(home, ".ssh", "id_ed25519");
  const defaultKnownHosts = path.join(home, ".ssh", "known_hosts");

  dependencies.write(`${heading("OpsHaven first-time setup", color)}\n\n`);
  dependencies.write("This wizard runs on your operator machine. Nothing is installed remotely until you run opshaven setup remote.\n\n");
  dependencies.write(`${section("Remote machine", color)}\n\n`);
  dependencies.write("Name is a friendly label shown in operator output.\n");
  const name = value(args, "--name") ?? await dependencies.ask("Name", "PRIMARY");
  dependencies.write("SSH address is the server hostname or IP address, optionally followed by :port.\n");
  const address = parseSshAddress(selectedAddress(args) ?? await dependencies.ask("SSH address"));
  const adminUser = value(args, "--admin-user") ?? await dependencies.ask("Administrator SSH user", "root");
  if (!USER.test(adminUser)) throw new OpsHavenError("CONFIG_INVALID", "The administrator SSH user is invalid.");

  dependencies.write("Administrator access is used only during installation. Choose an owner-only private key file.\n");
  const adminIdentity = absolute(value(args, "--admin-identity") ?? await dependencies.ask("Administrator SSH private key", defaultIdentity));
  if (!(await regularFile(adminIdentity, true))) {
    throw new OpsHavenError("CONFIG_INVALID", "Administrator SSH authentication is unavailable. The private key must be a safe owner-only regular file.");
  }

  dependencies.write("The known_hosts file pins the server identity and prevents connecting to an unexpected machine.\n");
  const knownHosts = absolute(value(args, "--known-hosts") ?? await dependencies.ask("Pinned known_hosts file", defaultKnownHosts));
  if (!(await regularFile(knownHosts, false))) {
    throw new OpsHavenError("CONFIG_INVALID", "Host identity unavailable. Provide a valid SSH fingerprint or configure a known_hosts source.");
  }

  dependencies.write(`\n${section("Host identity", color)}\n\n`);
  let fingerprint = value(args, "--host-key-sha256") ?? "";
  const detected = await detectKnownHostFingerprint(address.host, address.port, knownHosts);
  if (detected) {
    if (fingerprint && fingerprint !== detected) {
      throw new OpsHavenError("CONFIG_INVALID", "The provided SSH fingerprint does not match the pinned known_hosts source.");
    }
    fingerprint = detected;
    dependencies.write(`${paint("Detected host identity:", "info", color)}\n${fingerprint}\n\n`);
  } else {
    dependencies.write(`${paint("Host identity unavailable.", "warning", color)}\n\nProvide a valid SSH fingerprint or configure a known_hosts source.\n\n`);
    fingerprint = fingerprint || await dependencies.ask("Verified SHA-256 SSH fingerprint");
  }
  if (!FINGERPRINT.test(fingerprint)) {
    throw new OpsHavenError("CONFIG_INVALID", "Host identity unavailable. Provide a valid SSH fingerprint or configure a known_hosts source.");
  }
  if (!confirmationAccepted(await dependencies.ask("Use this host identity? [y/N]"), false)) {
    throw new OpsHavenError("POLICY_DENIED", "Host identity was not accepted. No setup state was created.");
  }
  dependencies.write(`${statusLine("passed", "Host identity verified", undefined, color)}\n\n`);

  dependencies.write(`${section("Ready to initialize", color)}\n\n`);
  dependencies.write(`Name: ${name}\nSSH address: ${address.host}:${address.port}\nAdministrator: ${adminUser}\nHost identity: ${fingerprint}\n\n`);
  dependencies.write("OpsHaven will now create protected local operator state. It will not contact or modify the remote machine.\n");
  if (!confirmationAccepted(await dependencies.ask("Continue? [Y/n]"), true)) {
    throw new OpsHavenError("POLICY_DENIED", "First-time setup was cancelled. No setup state was created.");
  }

  await dependencies.initialize(initArguments(args, address, adminUser, adminIdentity, knownHosts, fingerprint));
}

export async function runFirstRunWizard(args: readonly string[]): Promise<void> {
  if ((process.stdin as any).isTTY !== true || args.includes("--non-interactive") || args.includes("--local-only")) {
    await runInit(args);
    return;
  }
  const terminal = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  try {
    await executeFirstRunWizard(args, {
      interactive: true,
      ask: async (question, fallback = "") => {
        const suffix = fallback ? ` [${fallback}]` : "";
        const answer = (await terminal.question(`${question}${suffix}: `)).trim();
        return answer || fallback;
      },
      write: (output) => process.stdout.write(output),
      initialize: async (initArgs) => await runInit(initArgs),
    });
  } finally {
    terminal.close();
  }
}
