import { promises as fs } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { executeFirstRunWizard, runFirstRunWizard } from "./operator-init.js";
import { resolveSetupConfigPath, runInit } from "./operator-state.js";
import { parseRemoteSetupConfig } from "./setup/remote.js";

function onePassOutput(raw: string): string {
  const revised = raw
    .replace(/reviewed read-only runtime/g, "reviewed controlled runtime")
    .replace(/\nNext:\s*\nopshaven setup remote\s*$/s, "");
  return `${revised.trimEnd()}\n\nNext:\nRegister a deployment application:\n\n  opshaven app add\n\nThen install the complete reviewed remote runtime:\n\n  opshaven setup remote\n`;
}

function packageRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
}

async function normalizeGeneratedSetup(args: readonly string[]): Promise<void> {
  const setupPath = await resolveSetupConfigPath(args);
  if (!setupPath) return;
  const current = JSON.parse(await fs.readFile(setupPath, "utf8")) as Record<string, any>;
  if (!current.local || typeof current.local !== "object") return;
  const legacy = String(current.local.runtimeRoot ?? "").endsWith("/dist-readonly")
    || String(current.local.dispatcherPath ?? "").endsWith("/read-only-dispatcher.js");
  if (!legacy) return;
  const root = packageRoot();
  const next = {
    ...current,
    local: {
      ...current.local,
      runtimeRoot: path.join(root, "dist"),
      dispatcherPath: path.join(root, "dist/src/remote/dispatcher.js"),
      wrapperTemplatePath: path.join(root, "packaging/opshaven-controlled-force-command"),
    },
  };
  parseRemoteSetupConfig(next);
  const temporary = `${setupPath}.opshaven-${process.pid}-${Date.now()}`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    await fs.chmod(temporary, 0o600);
    await fs.rename(temporary, setupPath);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

async function initializeWithOnePassGuidance(args: readonly string[]): Promise<void> {
  if (args.includes("--json")) {
    await runInit(args);
    await normalizeGeneratedSetup(args);
    return;
  }
  const output = process.stdout;
  const original = output.write.bind(output);
  let captured = "";
  output.write = ((chunk: string | Uint8Array): boolean => {
    captured += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  }) as typeof output.write;
  try {
    await runInit(args);
    await normalizeGeneratedSetup(args);
  } finally {
    output.write = original as typeof output.write;
  }
  original(onePassOutput(captured));
}

export async function runOnePassFirstRunWizard(args: readonly string[]): Promise<void> {
  if (args.includes("--local-only")) {
    await runFirstRunWizard(args);
    return;
  }
  if ((process.stdin as { isTTY?: boolean }).isTTY !== true || args.includes("--non-interactive")) {
    await initializeWithOnePassGuidance(args);
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
      initialize: async (initArgs) => await initializeWithOnePassGuidance(initArgs),
    });
  } finally {
    terminal.close();
  }
}
