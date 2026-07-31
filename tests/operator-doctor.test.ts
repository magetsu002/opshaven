import assert from "node:assert/strict";
import test from "node:test";
import { formatDoctorReport, type DoctorReport } from "../src/operator-doctor.js";

function report(ok: boolean): DoctorReport {
  const passed = ok;
  return {
    ok,
    mode: "read-only",
    localOperatorEnvironment: [
      { label: "Approval signing key available", passed },
      { label: "Pinned host-key file available", passed },
    ],
    remoteDeploymentState: [
      { label: "Remote host reachable", passed },
      { label: "Runtime attestation matches", passed },
    ],
    authorizationArtifacts: [
      { label: "Capability authorization valid", passed },
      { label: "Signed policy artifacts valid", passed },
    ],
    endpointReadiness: [
      { label: "Endpoint policy valid", passed },
      { label: "Remote endpoint is read-only", passed },
    ],
    securityBoundaryStatus: [
      { label: "Boundary verification passed", passed },
      { label: "Audit chain valid", passed },
    ],
    endpoint: ok ? "READY" : "BLOCKED",
  };
}

test("doctor output separates operator, deployment, authorization, endpoint, and boundary status", () => {
  const text = formatDoctorReport(report(true));
  assert.match(text, /Local operator environment/);
  assert.match(text, /Remote deployment state/);
  assert.match(text, /Authorization artifacts/);
  assert.match(text, /Endpoint readiness/);
  assert.match(text, /Security boundary status/);
  assert.match(text, /✓ Runtime attestation matches/);
  assert.match(text, /Endpoint:\nREADY/);
});

test("doctor output marks failed readiness without exposing paths or secret material", () => {
  const value = report(false);
  value.remoteDeploymentState[0] = { label: "Remote host reachable", passed: false, detail: "verification did not complete" };
  const text = formatDoctorReport(value);
  assert.match(text, /✗ Remote host reachable — verification did not complete/);
  assert.match(text, /Endpoint:\nBLOCKED/);
  assert.doesNotMatch(text, /PRIVATE KEY|BEGIN [A-Z ]+ KEY|\/home\//);
});
