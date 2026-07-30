import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { parseConfig } from "../src/config/schema.js";
import { runDoctor } from "../src/diagnostics/doctor.js";
import { renderSudoers } from "../src/setup/sudoers.js";

describe("setup and diagnostics", () => {
  it("renders only exact configured sudo commands without wildcards", async () => {
    const config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
    const output = renderSudoers(config);
    assert.ok(output.includes("/usr/bin/systemctl restart demo.service"));
    assert.ok(!output.includes("*"));
    assert.ok(!output.includes("ALL=(ALL)"));
  });

  it("keeps the restricted account password-unusable without locking public-key authentication", async () => {
    const bootstrap = await readFile("scripts/bootstrap-dispatcher.sh", "utf8");
    const fixture = await readFile("integration/Dockerfile", "utf8");
    assert.ok(bootstrap.includes("usermod --password '*'"));
    assert.ok(fixture.includes("usermod --password '*'"));
    assert.ok(!bootstrap.includes("passwd -l"));
  });

  it("reports host-key, file, approval, executable, and audit status without values", async () => {
    const config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
    const report = await runDoctor(config, {
      accessPath: async () => undefined,
      inspectPath: async () => ({ isFile: () => true, isSymbolicLink: () => false }),
      verifyHost: async () => undefined,
      verifyAudit: async () => ({ valid: true, records: 2 }),
      environment: { OPSHAVEN_APPROVAL_KEY: "x".repeat(32) }
    });
    assert.equal(report.ok, true);
    assert.ok(JSON.stringify(report).includes("Approval key is present"));
    assert.ok(!JSON.stringify(report).includes("x".repeat(32)));
  });

  it("fails diagnostics for symlinked key material and host-key mismatch", async () => {
    const config = parseConfig(JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown);
    const report = await runDoctor(config, {
      accessPath: async () => undefined,
      inspectPath: async () => ({ isFile: () => true, isSymbolicLink: () => true }),
      verifyHost: async () => {
        throw new Error("mismatch");
      },
      verifyAudit: async () => ({ valid: true, records: 0 }),
      environment: { OPSHAVEN_APPROVAL_KEY: "x".repeat(32) }
    });
    assert.equal(report.ok, false);
  });
});
