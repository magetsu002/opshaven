import { createInterface } from "node:readline/promises";
import { colorEnabled, command, heading, numberedStatus, paint, sanitizeOperatorText, section, statusLine } from "../operator-ui.js";
import type { RemoteSetupPlan, SetupMutation, SetupStepState } from "./remote.js";

export interface SetupPresenter {
  plan(value: RemoteSetupPlan): void;
  step(id: string, scope: "local" | "vps", state: SetupStepState, detail: string): void;
  fingerprint(label: string, value: string): void;
  approve(message: string): Promise<boolean>;
  receipt(value: unknown): void;
}

const STAGES: Readonly<Record<string, readonly [number, string]>> = Object.freeze({
  preflight: [1, "Check installation prerequisites"],
  "runtime-install": [2, "Install the restricted runtime"],
  trust: [3, "Configure authorization"],
  boundary: [4, "Verify the security boundary"],
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
    if (id === "preflight") return "checking local tools, SSH access, platform, and permissions";
    if (id === "runtime-install") return "installing from the operator machine";
    if (id === "trust") return "preparing and applying authorization";
    if (id === "boundary") return "running remote security verification";
  }
  if (state === "passed") {
    if (id === "preflight") return sanitizeOperatorText(detail);
    if (id === "runtime-install") return "runtime installation completed";
    if (id === "trust") return "authorization configured";
    if (id === "boundary") return "security verification passed";
  }
  if (state === "failed") return sanitizeOperatorText(detail);
  if (state === "rolled-back") return "the previous remote state was restored";
  return undefined;
}

export class PlainSetupPresenter implements SetupPresenter {
  private readonly color = colorEnabled();
  private readonly debug = process.argv.includes("--debug");

  constructor(private readonly options: { nonInteractive: boolean; preapproved: boolean; json: boolean }) {}

  plan(value: RemoteSetupPlan): void {
    if (this.options.json) return;
    const localChanges = value.mutations.filter((item) => item.scope === "local").length;
    const remoteChanges = value.mutations.length - localChanges;
    process.stdout.write(`${heading("OpsHaven Remote Setup", this.color)}\n\n`);
    process.stdout.write(`${paint("Runs from:", "info", this.color)} operator machine\n`);
    process.stdout.write(`Remote setup target: ${value.target}\n`);
    process.stdout.write(`Source checkout: ${value.sourceSha.slice(0, 12)}\n`);
    process.stdout.write(`Planned changes: ${localChanges} local, ${remoteChanges} remote\n\n`);
    process.stdout.write(`${section("Checking", this.color)}\n\n`);
    if (this.debug) {
      process.stdout.write(`${section("Debug plan", this.color)}\n\n`);
      for (const item of value.mutations) process.stdout.write(`${mutationLine(item)}\n`);
      process.stdout.write("\n");
    }
  }

  step(id: string, scope: "local" | "vps", state: SetupStepState, detail: string): void {
    if (this.options.json) return;
    const stage = STAGES[id];
    if (stage) {
      const [index, label] = stage;
      const rendered = numberedStatus(index, 4, state, label, friendlyDetail(id, state, detail), this.color);
      process.stdout.write(`${rendered}\n`);
      return;
    }
    const label = id === "rollback" ? "Restore the previous remote state" : id;
    process.stdout.write(`${statusLine(state, label, `${scopeLabel(scope)} · ${friendlyDetail(id, state, detail) ?? sanitizeOperatorText(detail)}`, this.color)}\n`);
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
    try {
      return confirmationAccepted(await terminal.question(`${paint("Continue with remote installation? [y/N]", "warning", this.color)} `));
    } finally {
      terminal.close();
    }
  }

  receipt(value: unknown): void {
    if (this.options.json) {
      process.stdout.write(`${JSON.stringify(value)}\n`);
      return;
    }
    process.stdout.write(`\n${statusLine("passed", "Remote installation complete", undefined, this.color)}\n\n`);
    process.stdout.write(`${section("Next", this.color)}\n${command("opshaven doctor", this.color)}\n${command("opshaven boundary verify", this.color)}\n`);
  }
}

export class TuiSetupPresenter extends PlainSetupPresenter {
  override plan(value: RemoteSetupPlan): void {
    super.plan(value);
  }
}

export function createSetupPresenter(options: { tui: boolean; nonInteractive: boolean; preapproved: boolean; json: boolean }): SetupPresenter {
  const plain = { nonInteractive: options.nonInteractive, preapproved: options.preapproved, json: options.json };
  return options.tui ? new TuiSetupPresenter(plain) : new PlainSetupPresenter(plain);
}
