import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

test("remote trust installer grants only required dispatcher read access and preserves rollback metadata", () => {
  const source = readFileSync(path.join(process.cwd(), "packaging", "remote-trust-installer.py"), "utf8");
  assert.match(source, /"capability\.json": \(pathlib\.Path\(f"\{CONFIG\}\.capability\.json"\), 0o644\)/);
  assert.match(source, /"binding\.json": \(pathlib\.Path\(f"\{CONFIG\}\.declaration-binding\.json"\), 0o644\)/);
  assert.match(source, /runtime_gid = pwd\.getpwnam\("opshaven"\)\.pw_gid/);
  assert.match(source, /install_changed\(private_stage, RESPONSE_PRIVATE, 0o640, backup_root, journal, changed, 0, runtime_gid\)/);
  assert.match(source, /os\.chown\(destination, uid, gid\)/);
  assert.match(source, /os\.chown\(backup, original\.st_uid, original\.st_gid\)/);
  assert.doesNotMatch(source, /"(?:capability|binding)\.json"[^\n]+0o600/);
});
