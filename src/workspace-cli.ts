import { createInterface } from "node:readline/promises";
import { OpsHavenError } from "./errors.js";
import { WorkspaceStore, type WorkspacePermissions, type WorkspaceRecord } from "./workspace.js";

function option(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}

function enabled(value: string | undefined, label: string): boolean | undefined {
  if (value === undefined) return undefined;
  const normalized = value.toLowerCase();
  if (["on", "yes", "true", "1"].includes(normalized)) return true;
  if (["off", "no", "false", "0"].includes(normalized)) return false;
  throw new OpsHavenError("INVALID_ARGUMENTS", `${label} must be on or off.`);
}

function selectedPermissions(args: readonly string[]): Partial<WorkspacePermissions> {
  const result: Partial<WorkspacePermissions> = {};
  const values: Array<[keyof WorkspacePermissions, string]> = [
    ["read", "--read"],
    ["edit", "--edit"],
    ["tasks", "--tasks"],
    ["commands", "--commands"],
  ];
  for (const [key, flag] of values) {
    const value = enabled(option(args, flag), flag);
    if (value !== undefined) result[key] = value;
  }
  return result;
}

function yes(value: string, fallback: boolean): boolean {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return fallback;
  if (["y", "yes"].includes(normalized)) return true;
  if (["n", "no"].includes(normalized)) return false;
  throw new OpsHavenError("INVALID_ARGUMENTS", "Please answer yes or no.");
}

function permissionSummary(record: WorkspaceRecord): string {
  const value = record.permissions;
  return `read=${value.read ? "on" : "off"} edit=${value.edit ? "on" : "off"} tasks=${value.tasks ? "on" : "off"} commands=${value.commands ? "on" : "off"}`;
}

function printWorkspace(record: WorkspaceRecord): void {
  process.stdout.write(`${record.id}\n  Name: ${record.name}\n  Root: ${record.root}\n  Permissions: ${permissionSummary(record)}\n  Project: ${record.project.ecosystems.join(", ") || "unclassified"}${record.project.git ? ", git" : ""}\n`);
}

async function interactivePermissions(args: readonly string[]): Promise<Partial<WorkspacePermissions>> {
  const selected = selectedPermissions(args);
  if ((process.stdin as { isTTY?: boolean }).isTTY !== true || args.includes("--non-interactive")) return selected;
  const terminal = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  try {
    if (selected.read === undefined) selected.read = yes(await terminal.question("Can the AI read this project? [Y/n]: "), true);
    if (selected.edit === undefined) selected.edit = yes(await terminal.question("Can the AI edit files? [y/N]: "), false);
    if (selected.tasks === undefined) selected.tasks = yes(await terminal.question("Can the AI run project tasks such as tests and builds? [y/N]: "), false);
    if (selected.commands === undefined) selected.commands = yes(await terminal.question("Can the AI run broader terminal commands inside this project? [y/N]: "), false);
    return selected;
  } finally {
    terminal.close();
  }
}

function usage(): never {
  throw new OpsHavenError("INVALID_ARGUMENTS", "Usage: opshaven workspace add <directory> | list | info <id> | permissions <id> [--read on|off --edit on|off --tasks on|off --commands on|off]");
}

export async function runWorkspaceCommand(args: readonly string[], store = new WorkspaceStore()): Promise<void> {
  const subcommand = args[0];
  const json = args.includes("--json");
  if (subcommand === "add") {
    const root = args[1];
    if (!root || root.startsWith("--")) usage();
    const permissions = await interactivePermissions(args);
    const name = option(args, "--name");
    const record = await store.register(root, { ...(name ? { name } : {}), permissions });
    if (json) process.stdout.write(`${JSON.stringify(record)}\n`);
    else {
      process.stdout.write(`Workspace added: ${record.id}\n\n`);
      printWorkspace(record);
      process.stdout.write("\nNext:\n  opshaven connect\n");
    }
    return;
  }
  if (subcommand === "list") {
    const records = await store.list();
    if (json) process.stdout.write(`${JSON.stringify({ workspaces: records })}\n`);
    else if (records.length === 0) process.stdout.write("No local workspaces are registered.\n\nAdd one with:\n  opshaven workspace add <directory>\n");
    else {
      process.stdout.write("Local workspaces\n\n");
      for (const record of records) printWorkspace(record);
    }
    return;
  }
  if (subcommand === "info") {
    const id = args[1];
    if (!id || id.startsWith("--")) usage();
    const record = await store.refresh(id);
    if (json) process.stdout.write(`${JSON.stringify(record)}\n`);
    else printWorkspace(record);
    return;
  }
  if (subcommand === "permissions") {
    const id = args[1];
    if (!id || id.startsWith("--")) usage();
    const patch = selectedPermissions(args);
    if (Object.keys(patch).length === 0) {
      const record = await store.get(id);
      if (json) process.stdout.write(`${JSON.stringify({ workspaceId: record.id, permissions: record.permissions })}\n`);
      else process.stdout.write(`${record.id}: ${permissionSummary(record)}\n`);
      return;
    }
    const record = await store.updatePermissions(id, patch);
    if (json) process.stdout.write(`${JSON.stringify({ workspaceId: record.id, permissions: record.permissions })}\n`);
    else process.stdout.write(`Updated ${record.id}: ${permissionSummary(record)}\n`);
    return;
  }
  usage();
}

export async function runPermissionsCommand(args: readonly string[], store = new WorkspaceStore()): Promise<void> {
  const id = args[0];
  if (!id || id.startsWith("--")) throw new OpsHavenError("INVALID_ARGUMENTS", "Usage: opshaven permissions <workspace-id> [--read on|off --edit on|off --tasks on|off --commands on|off]");
  await runWorkspaceCommand(["permissions", id, ...args.slice(1)], store);
}

export function runConnectCommand(args: readonly string[]): void {
  const json = args.includes("--json");
  const command = "opshaven-mcp";
  const stdio = { transport: "stdio", command, args: [] as string[] };
  const chatgpt = {
    directLocalServer: false,
    guidance: "ChatGPT does not connect directly to a localhost MCP server. For ChatGPT, use OpenAI's supported Secure MCP Tunnel flow to bridge this local development environment without exposing an unauthenticated server publicly.",
  };
  if (json) {
    process.stdout.write(`${JSON.stringify({ mcp: stdio, chatgpt })}\n`);
    return;
  }
  process.stdout.write(`Connect an MCP client\n\nLocal MCP clients\n  Command: ${command}\n  Transport: stdio\n\nThe MCP server reads registered workspaces from ~/.config/opshaven/workspaces.json. A remote OpsHaven config is optional for local workspace work.\n\nChatGPT\n  ChatGPT does not connect directly to localhost MCP servers. Use OpenAI's supported Secure MCP Tunnel flow for a local/private development machine.\n\nTypical setup:\n  opshaven workspace list\n  opshaven connect\n`);
}
