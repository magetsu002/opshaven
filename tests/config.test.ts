import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { OpsHavenError } from "../src/core/errors.js";
import { parseConfig } from "../src/config/schema.js";

describe("configuration model", () => {
  it("parses the complete generic fixture", async () => {
    const fixture = JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as unknown;
    const config = parseConfig(fixture);
    assert.equal(config.hosts[0]?.id, "demo-host");
    assert.equal(config.deployments[0]?.migrationRisk, "manual-review");
  });

  it("rejects unknown fields at every trust boundary", async () => {
    const fixture = JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as Record<string, unknown>;
    fixture["shellCommand"] = "sh";
    assert.throws(() => parseConfig(fixture), (error: unknown) => {
      assert.ok(error instanceof OpsHavenError);
      assert.equal(error.code, "CONFIG_INVALID");
      return true;
    });
  });

  it("rejects traversal and cross-host references", async () => {
    const fixture = JSON.parse(await readFile("examples/opshaven.config.json", "utf8")) as {
      deployments: Array<Record<string, unknown>>;
    };
    fixture.deployments[0]!["repositoryPath"] = "/srv/demo/../secret";
    assert.throws(() => parseConfig(fixture), OpsHavenError);
  });
});
