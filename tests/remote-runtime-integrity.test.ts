import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import test from "node:test";

test("runtime reuse verifies installed bytes, file set, ownership, modes, and symlink absence", async () => {
  const installer = await fs.readFile(path.join(process.cwd(), "packaging", "remote-setup-installer.py"), "utf8");
  assert.match(installer, /def installed_runtime_matches\(entries\):/);
  assert.match(installer, /not RUNTIME_ROOT\.exists\(\) or RUNTIME_ROOT\.is_symlink\(\) or not RUNTIME_ROOT\.is_dir\(\)/);
  assert.match(installer, /set\(actual\.keys\(\)\) != set\(expected\.keys\(\)\)/);
  assert.match(installer, /info\.st_uid != 0 or info\.st_gid != 0/);
  assert.match(installer, /stat\.S_IMODE\(info\.st_mode\) != expected_mode/);
  assert.match(installer, /sha256_file\(candidate\) != digest/);
  assert.match(installer, /current\.get\("treeSha256"\) == manifest\.get\("treeSha256"\) and installed_runtime_matches\(entries\)/);
});
