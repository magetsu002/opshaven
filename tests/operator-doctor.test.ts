import assert from "node:assert/strict";
import test from "node:test";
import { formatDoctorReport, formatWorkflowReport, type DoctorReport, type OperatorWorkflowReport } from "../src/operator-doctor.js";

function report(ok: boolean): DoctorReport {
  const passed = ok;
  return {
    ok,
    mode: "read-only",
    localOperatorEnvironment: [
      { label: "Authorization signing available", passed },
      { label: "Pinned host identity available", passed },
    ],
    remoteDeploymentState: [
      { label: "Remote connection available", passed },
      { label: "Remote runtime verified", passed },
    ],
    authorizationArtifacts: [
      { label: "Authorization valid", passed },
      { label: "Deployment authorization valid", passed },
    ],
    endpointReadiness: [
      { label: "Endpoint configuration valid", passed },
      { label: "Remote endpoint is read-only", passed },
    ],
    securityBoundaryStatus: [
      { label: "Security boundary verified", passed },
      { label: "Audit history valid", passed },
    ],
    endpoint: ok ? "READY" : "BLOCKED",
  };
}

test("doctor output separates the operator troubleshooting areas", () => {
  const text = formatDoctorReport(report(true));
  assert.match(text, /^OpsHaven Health/);
  assert.match(text, /Local environment/);
  assert.match(text, /Remote connection/);
  assert.match(text, /Authorization state/);
  assert.match(text, /Security verification/);
  assert.match(text, /✓ Remote runtime verified/);
  assert.match(text, /Next action\nNo action required\./);
  assert.doesNotMatch(text, /capability|declaration binding|dispatcher|\.json|\.pem/i);
});

test("doctor output marks failed readiness without exposing paths or secret material", () => {
  const value = report(false);
  value.remoteDeploymentState[0] = { label: "Remote connection available", passed: false, detail: "verification did not complete" };
  const text = formatDoctorReport(value);
  assert.match(text, /✗ Remote connection available — verification did not complete/);
  assert.match(text, /opshaven doctor --debug/);
  assert.doesNotMatch(text, /PRIVATE KEY|BEGIN [A-Z ]+ KEY|\/home\//);
});

test("guided doctor output shows the exact next operator action", () => {
  const workflow: OperatorWorkflowReport = {
    ok: false,
    state: "LOCAL_INITIALIZED",
    completed: ["Operator keys", "Local configuration"],
    blocked: ["Remote deployment not configured"],
    nextAction: "opshaven setup remote",
  };
  const text = formatWorkflowReport(workflow);
  assert.match(text, /^OpsHaven Health/);
  assert.match(text, /Local environment\n✓ Operator setup ready/);
  assert.match(text, /Remote connection\n✗ Remote setup not configured/);
  assert.match(text, /Authorization state\n! Waiting for remote verification/);
  assert.match(text, /Security verification\n○ Not yet verified/);
  assert.match(text, /Next action\n  opshaven setup remote/);
  assert.doesNotMatch(text, /capability|declaration binding|dispatcher hash|\.json|\.pem/i);
});
