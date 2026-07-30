import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { startupBanner } from "../src/index.js";
import { VERSION } from "../src/version.js";

describe("project foundation", () => {
  it("exposes a deterministic startup identity", () => {
    assert.equal(startupBanner(), `OpsHaven MCP ${VERSION}`);
  });
});
