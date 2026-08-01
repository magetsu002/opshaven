import { createInterface } from "node:readline/promises";
import { colorEnabled, command, heading, numberedStatus, paint, sanitizeOperatorText, section, statusLine } from "../operator-ui.js";
import { formatRemoteSetupPlan, type RemoteSetupPlan, type SetupMutation, type SetupStepState } from "./remote.js";

export interface SetupPresenter {
  plan(value: RemoteSetupPlan): void;
  step(id: string, scope: "local" | "vps", state: SetupStepState, detail: string): void;
  progress?(id: string, detail: string, elapsedMs: number): void;
  cancellation?(mutationStarted: boolean, restored: boolean): void;
  fingerprint(label: string, value: string): void;
  approve(message: string): Promise<boolean>;
  receipt(value: unknown): void;
}

const STAGES: Readonly<Record<string, readonly [number, string]>> = Object.freeze({
  inspection: [1, "Inspect installed state"],
  preflight: [2, "Check installation prerequisites"],
  "runtime-install": [3, "Install the restricted runtime"],
  trust: [4, "Synchronize authorization"],
  boundary: [5, "Verify the security boundary"],
  readiness: [6, "Verify deployment readiness"],
});

function confirmationAccepted(answer: string): boolean {
  const normalized = answer.trim().toLowerCase();
  return normalized === "y" || normalized === "yes";
}

function mutationLine(item: SetupMutation): string {
  const scope = item.scope === "local" ? "OPERATOR" : "REMOTE";
  const risk = item.destructive ? "REPLACE" : item.action.toUpperCase();
  return `${scope.padEnd(8)} ${risk.padEnd(8)} ${item.path}\n           ${item.reason}`;
}

function scopeLabel(scope: "local" | "vps"): string {
  return scope === "local" ? "operator machine" : "remote machine";
}

function friendlyDetail(id: string, state: SetupStepState, detail: string): string | undefined {
  if (state === "pending") {
    if (id === "inspection") return "comparing verified content identities";
    if (id === "preflight") return "checking local tools, SSH access, platform, and permissions";
    if (id === "runtime-install") return "uploading and activating reviewed artifacts";
    if (id === "trust") return "applying only changed signed authorization";
    if (id === "boundary") return "running remote security verification";
    if (id === "readiness") return "confirming runtime, dispatcher, authorization, and scope";
  }
  if (state === "passed" || state === "skipped" || state === "failed") return sanitizeOperatorText(detail);
  if (state === "rolled-back") return "the previous verified remote state was restored";
  return undefined;
}

function applicationId(value: unknown): string | null {
  if (!Array.isArray(value) || value.length === 0 || typeof value[0] !== "string") return null;
  const selected = value[0];
  if (selected.startsWith("app.")) return selected.slice(4);
  return /^[a-z][a-z0-9-]{0,63}$/.test(selected) ? selected : null;
}

function applicationLabel(id: string): string {
  return id.split("-").filter(Boolean).map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`).join(" ");
}

export class PlainSetupPresenter implements SetupPresenter {
  private readonly color = colorEnabled();
  private readonly debug = process.argv.includes("--debug");
  private progressOpen = false;

  constructor(private readonly options: { nonInteractive: boolean; preapproved: boolean; json: boolean }) {}

  plan(value: RemoteSetupPlan): void {
    if (this.options.json) return;
    process.stdout.write(`${heading("OpsHaven Remote Setup", this.color)}\n\n`);
    process.stdout.write(formatRemoteSetupPlan(value));
    if (["FULL_INSTALL", "RUNTIME_UPDATE", "DISPATCHER_UPDATE"].includes(value.changeType)) {
      process.stdout.write("\nThe first remote installation usually takes 1–3 minutes.\nLater synchronization runs are normally much faster.\nDo not close this terminal while a step is active.\n");
    } else if (value.changeType === "NO_CHANGE") {
      process.stdout.write("\nThis target is already installed.\nOpsHaven will verify the existing state without reinstalling it.\n");
    } else if (value.changeType === "AUTHORIZATION_ONLY") {
      process.stdout.write("\nOnly signed authorization state needs updating.\nThe installed runtime and dispatcher will be reused.\n");
    } else if (value.changeType === "APPLICATION_DECLARATION_ONLY") {
      process.stdout.write("\nOnly the reviewed deployment application declaration needs updating.\nThe installed runtime and dispatcher will be reused.\n");
    } else if (value.changeType === "AUTHORIZATION_AND_DECLARATION") {
      process.stdout.write("\nOnly signed authorization and reviewed declaration state need updating.\nThe installed runtime and dispatcher will be reused.\n");
    }
    if (this.debug) {
      process.stdout.write(`\n${section("Debug plan", this.color)}\n\n`);
      for (const item of value.mutations) process.stdout.write(`${mutationLine(item)}\n`);
    }
    process.stdout.write("\n");
  }

  step(id: string, scope: "local" | "vps", state: SetupStepState, detail: string): void {
    if (this.options.json) return;
    if (this.progressOpen && (process.stdout as any).isTTY) {
      process.stdout.write("\n");
      this.progressOpen = false;
    }
    const stage = STAGES[id];
    if (stage) {
      const [index, label] = stage;
      process.stdout.write(`${numberedStatus(index, 6, state, label, friendlyDetail(id, state, detail), this.color)}\n`);
      return;
    }
    const label = id === "rollback" ? "Restore the previous remote state" : id;
    process.stdout.write(`${statusLine(state, label, `${scopeLabel(scope)} · ${friendlyDetail(id, state, detail) ?? sanitizeOperatorText(detail)}`, this.color)}\n`);
  }

  progress(id: string, detail: string, elapsedMs: number): void {
    if (this.options.json) return;
    const stage = STAGES[id];
    const label = stage?.[1] ?? id;
    const elapsed = Math.floor(elapsedMs / 1000);
    const line = `${stage ? `[${stage[0]}/6] ` : ""}⏳ ${label} — ${sanitizeOperatorText(detail)}, ${elapsed}s elapsed`;
    if ((process.stdout as any).isTTY) {
      process.stdout.write(`\r${line}`);
      this.progressOpen = true;
    } else process.stdout.write(`${line}\n`);
  }

  cancellation(mutationStarted: boolean, restored: boolean): void {
    if (this.options.json) return;
    process.stdout.write(`\n${paint("Cancellation requested.", "warning", this.color)}\n\n`);
    process.stdout.write("OpsHaven is returning to the last verified checkpoint.\n\n");
    process.stdout.write(`${section("Changes made", this.color)}\n`);
    process.stdout.write(mutationStarted ? "  A controlled synchronization generation had started.\n" : "  No remote changes were made.\n");
    process.stdout.write(`\n${section("Rollback result", this.color)}\n`);
    if (!mutationStarted) process.stdout.write("  Rollback was not required.\n");
    else if (restored) process.stdout.write("  Previous verified installation restored and active.\n");
    else process.stdout.write("  Recovery requires operator attention.\n");
    process.stdout.write(`\n${section("Rerun safety", this.color)}\n`);
    process.stdout.write(!mutationStarted || restored ? "  Safe to rerun the same setup command.\n" : "  Inspect recovery state before rerunning.\n");
    process.stdout.write(`\n${section("Next", this.color)}\n${command(restored || !mutationStarted ? "opshaven setup remote" : "opshaven doctor --debug", this.color)}\n`);
  }

  fingerprint(label: string, value: string): void {
    if (this.options.json) return;
    if (label === "SSH host key") {
      process.stdout.write(`\n${section("Host identity", this.color)}\n${value}\n\n`);
      return;
    }
    if (this.debug) process.stdout.write(`${paint("Debug verification:", "info", this.color)} ${label} ${value}\n`);
  }

  async approve(_message: string): Promise<boolean> {
    if (this.options.preapproved) return true;
    if (this.options.nonInteractive) return false;
    const terminal = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    try { return confirmationAccepted(await terminal.question(`${paint("Continue with remote synchronization? [y/N]", "warning", this.color)} `)); }
    finally { terminal.close(); }
  }

  receipt(value: unknown): void {
    if (this.options.json) {
      process.stdout.write(`${JSON.stringify(value)}\n`);
      return;
    }
    const record = value as Record<string, any>;
    const app = applicationId(record.canonicalState?.desired?.applicationScope);
    process.stdout.write(`\n${statusLine("passed", "Remote setup complete", undefined, this.color)}\n`);
    process.stdout.write(`${statusLine("passed", "Deployment capability synchronized", undefined, this.color)}\n`);
    process.stdout.write(`${statusLine("passed", "Security boundary verified", undefined, this.color)}\n`);
    if (app) process.stdout.write(`${statusLine("passed", `${applicationLabel(app)} ready for planning`, undefined, this.color)}\n`);
    if (record.changeType === "NO_CHANGE") process.stdout.write("\nNo remote changes were required.\n");
    process.stdout.write(`\n${section("Next", this.color)}\n`);
    if (!app) {
      process.stdout.write("Register a deployment application:\n\n");
      process.stdout.write(`${command("opshaven app add", this.color)}\n`);
      return;
    }
    process.stdout.write("Create a deployment plan:\n\n");
    process.stdout.write(`${command(`opshaven deploy plan ${app}`, this.color)}\n`);
  }
}

export class TuiSetupPresenter extends PlainSetupPresenter {}

export function createSetupPresenter(options: { tui: boolean; nonInteractive: boolean; preapproved: boolean; json: boolean }): SetupPresenter {
  const plain = { nonInteractive: options.nonInteractive, preapproved: options.preapproved, json: options.json };
  return options.tui ? new TuiSetupPresenter(plain) : new PlainSetupPresenter(plain);
}
