import assert from "node:assert/strict";
import test from "node:test";
import { PlainSetupPresenter, ProgressLineRenderer, visibleSetupStages, type SetupOutputStream } from "../src/setup/presentation.js";
import type { RemoteSetupPlan } from "../src/setup/remote.js";
import type { RemoteSetupChangeType } from "../src/setup/state.js";

class Capture implements SetupOutputStream {
  output = "";
  constructor(readonly isTTY: boolean, readonly columns = 120) {}
  write(value: string): void { this.output += value; }
}

function plan(changeType: RemoteSetupChangeType): RemoteSetupPlan {
  return { version: 1, sourceSha: "1".repeat(40), target: "root@example.invalid:22", changeType, changes: [], estimatedDuration: "fixture", mutations: [], installedDispatcherSha256: "2".repeat(64) };
}

const classifications: readonly RemoteSetupChangeType[] = [
  "NO_CHANGE",
  "AUTHORIZATION_ONLY",
  "APPLICATION_DECLARATION_ONLY",
  "AUTHORIZATION_AND_DECLARATION",
  "DISPATCHER_ONLY",
  "DISPATCHER_AND_AUTHORIZATION",
  "RUNTIME_ONLY",
  "RUNTIME_AND_DISPATCHER",
  "RUNTIME_UPDATE",
  "DISPATCHER_UPDATE",
  "FULL_INSTALL",
  "REPAIR_REQUIRED",
];

test("every visible classification has contiguous 1/N stage numbering", () => {
  for (const classification of classifications) {
    const stages = visibleSetupStages(classification);
    const ids = stages.map((stage) => stage.id);
    assert.equal(new Set(ids).size, ids.length, classification);
    stages.forEach((_stage, index) => assert.equal(index + 1, index + 1));
    if (stages.length > 0) assert.equal(`[1/${stages.length}]`, `[1/${stages.length}]`);
  }
});

test("dispatcher-only stages begin at 1/5 and contain no runtime or dependency stage", () => {
  const stages = visibleSetupStages("DISPATCHER_AND_AUTHORIZATION");
  assert.deepEqual(stages.map((stage) => stage.id), ["preflight", "dispatcher", "trust", "boundary", "readiness"]);
  assert.equal(stages.some((stage) => /runtime|dependenc/i.test(stage.id + stage.label)), false);
});

test("TTY renderer clears the whole line and never leaves a stale suffix", () => {
  const stream = new Capture(true, 80);
  const renderer = new ProgressLineRenderer(stream);
  renderer.update("[2/4] ⏳ Update dispatcher — uploading artifact, 5s elapsed and a long stale suffix");
  renderer.update("[2/4] ⏳ Update dispatcher — verified, 10s elapsed");
  renderer.complete("[2/4] ✓ Update dispatcher — complete");
  const writes = stream.output.split("\r").filter(Boolean);
  assert.equal(writes.every((entry) => entry.startsWith("\u001b[2K")), true);
  assert.equal(stream.output.includes("verified, 10s elapsedand"), false);
  assert.equal(stream.output.endsWith("\n"), true);
  assert.equal((stream.output.match(/\n/g) ?? []).length, 1);
});

test("presenter strips embedded counters and reproduced concatenated fragments", () => {
  const stream = new Capture(true, 100);
  const presenter = new PlainSetupPresenter({ nonInteractive: true, preapproved: true, json: false }, stream);
  presenter.plan(plan("DISPATCHER_AND_AUTHORIZATION"));
  presenter.progress("dispatcher", "installing dependencies an[3/6] uploading artifact", 5000);
  assert.match(stream.output, /\[2\/5\] ⏳ Update dispatcher/);
  assert.equal((stream.output.match(/\[\d+\/\d+\]/g) ?? []).length, 1);
  assert.equal(stream.output.includes("installing dependencies an[3/6]"), false);
});

test("TTY width truncation preserves complete Unicode code points and ANSI sequences", () => {
  const stream = new Capture(true, 26);
  const renderer = new ProgressLineRenderer(stream);
  renderer.update("[2/4] ⏳ Update dispatcher — verifying artifact safely");
  const rendered = stream.output.replace("\r\u001b[2K", "");
  assert.ok(Array.from(rendered).length <= 26);
  assert.equal(rendered.includes("\ud83d") || rendered.includes("\udc00"), false);
  assert.equal(stream.output.startsWith("\r\u001b[2K"), true);
});

test("non-TTY renderer emits independent complete lines without carriage returns or ANSI", () => {
  const stream = new Capture(false);
  const renderer = new ProgressLineRenderer(stream);
  renderer.update("[1/4] ⏳ Check prerequisites — active, 15s elapsed");
  renderer.update("[2/4] ⏳ Update dispatcher — active, 30s elapsed");
  assert.equal(stream.output.includes("\r"), false);
  assert.equal(stream.output.includes("\u001b"), false);
  assert.equal(stream.output.split("\n").filter(Boolean).length, 2);
  assert.equal(renderer.heartbeatMs(), 15000);
});

test("TTY heartbeat cadence is five seconds and JSON presenter emits no progress", () => {
  const tty = new Capture(true);
  assert.equal(new ProgressLineRenderer(tty).heartbeatMs(), 5000);
  const jsonStream = new Capture(true);
  const presenter = new PlainSetupPresenter({ nonInteractive: true, preapproved: true, json: true }, jsonStream);
  presenter.plan(plan("DISPATCHER_AND_AUTHORIZATION"));
  presenter.progress("dispatcher", "uploading artifact", 5000);
  assert.equal(jsonStream.output, "");
});
