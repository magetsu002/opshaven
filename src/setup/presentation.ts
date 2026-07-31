import { createInterface } from "node:readline/promises";
import type { RemoteSetupPlan, SetupMutation, SetupStepState } from "./remote.js";

export interface SetupPresenter {
  plan(value: RemoteSetupPlan): void;
  step(id: string, scope: "local" | "vps", state: SetupStepState, detail: string): void;
  fingerprint(label: string, value: string): void;
  approve(message: string): Promise<boolean>;
  receipt(value: unknown): void;
}

function mutationLine(item: SetupMutation): string {
  const scope = item.scope === "local" ? "LOCAL" : "VPS";
  const risk = item.destructive ? "REPLACE" : item.action.toUpperCase();
  return `${scope.padEnd(5)} ${risk.padEnd(8)} ${item.path}\n      ${item.reason}`;
}

export class PlainSetupPresenter implements SetupPresenter {
  constructor(private readonly options: { nonInteractive: boolean; preapproved: boolean; json: boolean }) {}

  plan(value: RemoteSetupPlan): void {
    if (this.options.json) return;
    process.stdout.write(`Remote setup target: ${value.target}\nExact source: ${value.sourceSha}\n`);
    for (const item of value.mutations) process.stdout.write(`${mutationLine(item)}\n`);
  }

  step(id: string, scope: "local" | "vps", state: SetupStepState, detail: string): void {
    if (this.options.json) return;
    process.stdout.write(`${state.toUpperCase().padEnd(11)} ${scope.toUpperCase().padEnd(5)} ${id}: ${detail}\n`);
  }

  fingerprint(label: string, value: string): void {
    if (!this.options.json) process.stdout.write(`VERIFY      ${label}: ${value}\n`);
  }

  async approve(message: string): Promise<boolean> {
    if (this.options.preapproved) return true;
    if (this.options.nonInteractive) return false;
    const terminal = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    try { return (await terminal.question(`${message} Type YES to continue: `)).trim() === "YES"; }
    finally { terminal.close(); }
  }

  receipt(value: unknown): void {
    process.stdout.write(`${JSON.stringify(value, null, this.options.json ? 0 : 2)}\n`);
  }
}

export class TuiSetupPresenter extends PlainSetupPresenter {
  private readonly interactive = process.stdout.isTTY === true;

  override plan(value: RemoteSetupPlan): void {
    if (this.interactive) process.stdout.write("\u001b[2J\u001b[H\u001b[1mOpsHaven secure remote setup\u001b[0m\n\n");
    super.plan(value);
    process.stdout.write("\nSecurity decisions remain explicit; no command or mutation is hidden.\n\n");
  }

  override step(id: string, scope: "local" | "vps", state: SetupStepState, detail: string): void {
    const markers: Record<SetupStepState, string> = { pending: "…", passed: "✓", failed: "✗", skipped: "–", "rolled-back": "↶" };
    if (this.interactive) process.stdout.write(`${markers[state]} ${scope === "local" ? "Local" : "VPS"} · ${id} · ${detail}\n`);
    else super.step(id, scope, state, detail);
  }
}

export function createSetupPresenter(options: { tui: boolean; nonInteractive: boolean; preapproved: boolean; json: boolean }): SetupPresenter {
  const plain = { nonInteractive: options.nonInteractive, preapproved: options.preapproved, json: options.json };
  return options.tui ? new TuiSetupPresenter(plain) : new PlainSetupPresenter(plain);
}
