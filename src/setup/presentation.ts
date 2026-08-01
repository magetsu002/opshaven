import { createInterface } from "node:readline/promises";
import { colorEnabled, command, heading, numberedStatus, paint, sanitizeOperatorText, section, statusLine } from "../operator-ui.js";
import { formatRemoteSetupPlan, type RemoteSetupPlan, type SetupMutation, type SetupStepState } from "./remote.js";
import type { RemoteSetupChangeType } from "./state.js";

export interface SetupPresenter {
  plan(value: RemoteSetupPlan): void;
  step(id: string, scope: "local" | "vps", state: SetupStepState, detail: string): void;
  progress?(id: string, detail: string, elapsedMs: number): void;
  heartbeatMs?(): number;
  cancellation?(mutationStarted: boolean, restored: boolean): void;
  fingerprint(label: string, value: string): void;
  approve(message: string): Promise<boolean>;
  receipt(value: unknown): void;
}

export interface SetupOutputStream {
  readonly isTTY?: boolean;
  readonly columns?: number;
  write(value: string): unknown;
}

export interface VisibleSetupStage {
  readonly id: string;
  readonly label: string;
}

const LABELS = Object.freeze({
  preflight: "Check prerequisites",
  runtimeUpload: "Upload runtime",
  runtimeInstall: "Install runtime",
  dispatcher: "Update dispatcher",
  trust: "Synchronize authorization",
  boundary: "Verify security boundary",
  readiness: "Certify canonical readiness",
});

export function visibleSetupStages(changeType: RemoteSetupChangeType): readonly VisibleSetupStage[] {
  switch (changeType as string) {
    case "FULL_INSTALL":
      return Object.freeze([
        { id: "preflight", label: LABELS.preflight },
        { id: "runtime-upload", label: LABELS.runtimeUpload },
        { id: "runtime-install", label: LABELS.runtimeInstall },
        { id: "trust", label: "Configure authorization" },
        { id: "boundary", label: "Verify dispatcher compatibility" },
        { id: "readiness", label: LABELS.boundary },
      ]);
    case "RUNTIME_UPDATE":
    case "RUNTIME_ONLY":
    case "RUNTIME_AND_DISPATCHER":
      return Object.freeze([
        { id: "preflight", label: LABELS.preflight },
        { id: "runtime-upload", label: LABELS.runtimeUpload },
        { id: "runtime-install", label: LABELS.runtimeInstall },
        { id: "trust", label: LABELS.trust },
        { id: "boundary", label: "Verify dispatcher compatibility" },
        { id: "readiness", label: LABELS.boundary },
      ]);
    case "DISPATCHER_UPDATE":
    case "DISPATCHER_ONLY":
    case "DISPATCHER_AND_AUTHORIZATION":
      return Object.freeze([
        { id: "preflight", label: LABELS.preflight },
        { id: "dispatcher", label: LABELS.dispatcher },
        { id: "trust", label: LABELS.trust },
        { id: "boundary", label: LABELS.boundary },
        { id: "readiness", label: LABELS.readiness },
      ]);
    case "AUTHORIZATION_ONLY":
    case "APPLICATION_DECLARATION_ONLY":
    case "AUTHORIZATION_AND_DECLARATION":
      return Object.freeze([
        { id: "trust", label: LABELS.trust },
        { id: "boundary", label: LABELS.boundary },
        { id: "readiness", label: LABELS.readiness },
      ]);
    case "NO_CHANGE":
      return Object.freeze([
        { id: "boundary", label: LABELS.boundary },
        { id: "readiness", label: LABELS.readiness },
      ]);
    default:
      return Object.freeze([]);
  }
}

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
    if (id === "runtime-upload") return "uploading and verifying the reviewed runtime archive";
    if (id === "runtime-install") return "activating the reviewed runtime generation";
    if (id === "dispatcher") return "uploading and verifying the dispatcher artifact";
    if (id === "trust") return "applying only changed signed authorization";
    if (id === "boundary") return "running authenticated remote security verification";
    if (id === "readiness") return "confirming runtime, dispatcher, authorization, and scope";
  }
  if (state === "passed" || state === "skipped" || state === "failed") return sanitizeOperatorText(detail);
  if (state === "rolled-back") return "the previous verified generation was restored";
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

function stripEmbeddedCounter(value: string): string {
  return value.replace(/\[\d+\/\d+\]/g, "").replace(/\s{2,}/g, " ").trim();
}

function truncateComplete(value: string, width: number): string {
  if (!Number.isSafeInteger(width) || width < 8) return "";
  const characters = Array.from(value);
  if (characters.length <= width) return value;
  return `${characters.slice(0, Math.max(1, width - 1)).join("")}…`;
}

export class ProgressLineRenderer {
  private active = false;
  private finalized = false;

  constructor(private readonly stream: SetupOutputStream) {}

  isTTY(): boolean { return this.stream.isTTY === true; }
  heartbeatMs(): number { return this.isTTY() ? 5000 : 15000; }
  hasActiveLine(): boolean { return this.active; }

  private bounded(value: string): string {
    const sanitized = value.replace(/[\r\n\u001b\u009b]/g, " ");
    if (!this.isTTY()) return sanitized;
    const width = typeof this.stream.columns === "number" ? Math.max(8, this.stream.columns) : 120;
    return truncateComplete(sanitized, width);
  }

  update(value: string): void {
    if (this.finalized) return;
    const line = this.bounded(value);
    if (this.isTTY()) {
      this.stream.write(`\r\u001b[2K${line}`);
      this.active = true;
    } else {
      this.stream.write(`${line}\n`);
    }
  }

  complete(value: string): void {
    if (this.finalized) return;
    const line = this.bounded(value);
    if (this.isTTY() && this.active) this.stream.write(`\r\u001b[2K${line}\n`);
    else this.stream.write(`${line}\n`);
    this.active = false;
  }

  finish(): void {
    if (this.finalized) return;
    if (this.isTTY() && this.active) this.stream.write("\r\u001b[2K\n");
    this.active = false;
    this.finalized = true;
  }
}

export class PlainSetupPresenter implements SetupPresenter {
  private readonly color = colorEnabled();
  private readonly debug = process.argv.includes("--debug");
  private readonly renderer: ProgressLineRenderer;
  private stages: readonly VisibleSetupStage[] = Object.freeze([]);
  private readonly stageIndex = new Map<string, number>();
  private runtimeUploadActive = false;

  constructor(
    private readonly options: { nonInteractive: boolean; preapproved: boolean; json: boolean },
    stream: SetupOutputStream = process.stdout as SetupOutputStream,
  ) {
    this.renderer = new ProgressLineRenderer(stream);
  }

  heartbeatMs(): number { return this.renderer.heartbeatMs(); }

  private numbered(id: string, state: SetupStepState, detail: string): string | null {
    const index = this.stageIndex.get(id);
    if (index === undefined) return null;
    const label = this.stages[index - 1]?.label ?? id;
    return numberedStatus(index, this.stages.length, state, label, friendlyDetail(id, state, detail), this.color);
  }

  private writeCompleted(line: string): void {
    if (this.renderer.hasActiveLine()) this.renderer.complete(line);
    else process.stdout.write(`${line}\n`);
  }

  plan(value: RemoteSetupPlan): void {
    this.stages = visibleSetupStages(value.changeType);
    this.stageIndex.clear();
    this.runtimeUploadActive = false;
    this.stages.forEach((stage, index) => this.stageIndex.set(stage.id, index + 1));
    if (this.options.json) return;
    process.stdout.write(`${heading("OpsHaven Remote Setup", this.color)}\n\n`);
    process.stdout.write(formatRemoteSetupPlan(value));
    if (["FULL_INSTALL", "RUNTIME_UPDATE", "RUNTIME_ONLY", "RUNTIME_AND_DISPATCHER"].includes(value.changeType as string)) {
      process.stdout.write("\nFirst installation may take up to a few minutes.\nDispatcher-only and authorization-only updates should normally be faster.\nDo not close this terminal while a step is active.\n");
    } else if (["DISPATCHER_UPDATE", "DISPATCHER_ONLY", "DISPATCHER_AND_AUTHORIZATION"].includes(value.changeType as string)) {
      process.stdout.write("\nThe verified runtime will be reused. Only the dispatcher and matching authorization will be synchronized.\n");
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
    if (id === "runtime-install" && this.stageIndex.has("runtime-upload")) {
      if (state === "pending") {
        const upload = this.numbered("runtime-upload", "pending", "uploading and verifying the reviewed runtime archive");
        if (upload) this.writeCompleted(upload);
        this.runtimeUploadActive = true;
        return;
      }
      if (this.runtimeUploadActive) {
        const uploadState: SetupStepState = state === "passed" ? "passed" : state === "failed" ? "failed" : state;
        const uploadDetail = state === "passed" ? "reviewed runtime archive uploaded and verified" : detail;
        const upload = this.numbered("runtime-upload", uploadState, uploadDetail);
        if (upload) this.writeCompleted(upload);
        this.runtimeUploadActive = false;
        if (state !== "passed") return;
      }
    }

    const numbered = this.numbered(id, state, detail);
    if (numbered) {
      this.writeCompleted(numbered);
      return;
    }
    if (state === "skipped") return;
    const label = id === "rollback" ? "Restore the previous remote state" : id;
    const line = statusLine(state, label, `${scopeLabel(scope)} · ${friendlyDetail(id, state, detail) ?? sanitizeOperatorText(detail)}`, this.color);
    this.writeCompleted(line);
  }

  progress(id: string, detail: string, elapsedMs: number): void {
    if (this.options.json) return;
    const visibleId = id === "runtime-install" && this.runtimeUploadActive ? "runtime-upload" : id;
    const index = this.stageIndex.get(visibleId);
    if (index === undefined) return;
    const label = this.stages[index - 1]?.label ?? visibleId;
    const elapsed = Math.max(0, Math.floor(elapsedMs / 1000));
    const safeDetail = stripEmbeddedCounter(sanitizeOperatorText(detail));
    this.renderer.update(`[${index}/${this.stages.length}] ⏳ ${label} — ${safeDetail}, ${elapsed}s elapsed`);
  }

  cancellation(mutationStarted: boolean, restored: boolean): void {
    if (this.options.json) return;
    this.renderer.finish();
    process.stdout.write(`${paint("Cancellation requested.", "warning", this.color)}\n\n`);
    process.stdout.write("OpsHaven is returning to the last verified checkpoint.\n\n");
    process.stdout.write(`${section("Changes made", this.color)}\n`);
    process.stdout.write(mutationStarted ? "  A controlled synchronization generation had started.\n" : "  No active generation was changed.\n");
    process.stdout.write(`\n${section("Rollback result", this.color)}\n`);
    if (!mutationStarted) process.stdout.write("  Rollback was not required.\n");
    else if (restored) process.stdout.write("  Previous verified generation restored and active.\n");
    else process.stdout.write("  Recovery requires operator attention.\n");
    process.stdout.write(`\n${section("Rerun safety", this.color)}\n`);
    process.stdout.write(!mutationStarted || restored ? "  Safe to rerun the same setup command.\n" : "  Deployment operations remain blocked until reviewed recovery succeeds.\n");
    process.stdout.write(`\n${section("Next", this.color)}\n${command(restored || !mutationStarted ? "opshaven setup remote" : "opshaven setup repair", this.color)}\n`);
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
    this.renderer.finish();
    const record = value as Record<string, any>;
    const app = applicationId(record.canonicalState?.desired?.applicationScope);
    process.stdout.write(`${statusLine("passed", "Remote setup complete", undefined, this.color)}\n`);
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
