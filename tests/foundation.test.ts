import assert from "node:assert/strict";
import test from "node:test";

test("foundation uses a supported runtime", () => {
  assert.ok(Number(process.versions?.node?.split(".")[0] ?? 0) >= 22);
});
