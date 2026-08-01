import assert from "node:assert/strict";
import test from "node:test";
import { colorEnabled, formatOperatorFailure, paint, sanitizeOperatorText, statusLine } from "../src/operator-ui.js";

test("terminal colors are disabled for non-color environments", () => {
  assert.equal(colorEnabled({ NO_COLOR: "" }, { isTTY: true }), false);
  assert.equal(colorEnabled({ TERM: "dumb" }, { isTTY: true }), false);
  assert.equal(colorEnabled({}, { isTTY: false }), false);
  assert.equal(paint("ok", "success", false), "ok");
  assert.doesNotMatch(statusLine("passed", "Ready", undefined, false), /\u001b\[/);
});

test("terminal colors can be enabled explicitly without changing text meaning", () => {
  assert.equal(colorEnabled({ OPSHAVEN_COLOR: "always" }, { isTTY: false }), true);
  const rendered = statusLine("failed", "Blocked", undefined, true);
  assert.match(rendered, /\u001b\[31m/);
  assert.match(rendered, /✗.*Blocked/);
});

test("operator errors remain structured and hide implementation terminology", () => {
  const rendered = formatOperatorFailure({
    title: "Remote setup cannot continue",
    cause: "Declaration binding failed for /home/operator/private/config.json and capability artifacts.",
    checked: [
      { label: "Host identity", state: "passed" },
      { label: "SSH authentication", state: "failed" },
    ],
    next: "Verify administrator access.",
    run: "opshaven doctor",
  }, false);
  assert.match(rendered, /Cause:/);
  assert.match(rendered, /Checked:/);
  assert.match(rendered, /Next:/);
  assert.match(rendered, /Run:\n  opshaven doctor/);
  assert.match(rendered, /<protected path>/);
  assert.doesNotMatch(rendered, /declaration binding|capability artifacts|\/home\/operator/i);
});

test("operator text sanitizer translates lower-level wording", () => {
  const text = sanitizeOperatorText("Capability authorization and dispatcher declaration binding failed.");
  assert.match(text, /authorization/i);
  assert.match(text, /remote runtime/);
  assert.match(text, /deployment verification/);
  assert.doesNotMatch(text, /capability|dispatcher|declaration binding/i);
});
