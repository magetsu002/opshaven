import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const sourcePath = path.resolve("packaging/opshaven-readonly-force-command");
const source = readFileSync(sourcePath, "utf8");
for (const required of [
  "--no-new-privs",
  "--inh-caps=-all",
  "--ambient-caps=-all",
  "--reset-env",
  "/usr/bin/node /usr/lib/opshaven/read-only-dispatcher.js",
]) {
  assert.ok(source.includes(required), `wrapper must retain ${required}`);
}
assert.equal(source.includes("--bounding-set"), false, "unprivileged wrapper must not modify the capability bounding set");

const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
const directory = mkdtempSync(path.join(os.tmpdir(), "opshaven-readonly-wrapper-"));
chmodSync(directory, 0o755);
try {
  const dispatcher = path.join(directory, "dispatcher.mjs");
  const wrapper = path.join(directory, "force-command");
  writeFileSync(
    dispatcher,
    'process.stdout.write(JSON.stringify({ argv: process.argv.slice(2), originalCommand: process.env.SSH_ORIGINAL_COMMAND ?? null, path: process.env.PATH, home: process.env.HOME, lang: process.env.LANG, lcAll: process.env.LC_ALL }) + "\\n");\n',
    { mode: 0o755 },
  );
  const harness = source.replace(
    "/usr/bin/node /usr/lib/opshaven/read-only-dispatcher.js",
    `${quote(process.execPath)} ${quote(dispatcher)}`,
  );
  assert.notEqual(harness, source, "test harness must replace only the fixed dispatcher executable");
  writeFileSync(wrapper, harness, { mode: 0o755 });

  const run = (args) => {
    const options = {
      encoding: "utf8",
      env: { ...process.env, SSH_ORIGINAL_COMMAND: "id" },
    };
    if (typeof process.getuid === "function" && process.getuid() === 0) {
      return spawnSync("/usr/bin/setpriv", ["--reuid=65534", "--regid=65534", "--clear-groups", wrapper, ...args], options);
    }
    return spawnSync(wrapper, args, options);
  };

  const launched = run(["--config", "/etc/opshaven/read-only.json"]);
  assert.equal(launched.status, 0, launched.stderr);
  const payload = JSON.parse(launched.stdout);
  assert.deepEqual(payload.argv, ["--config", "/etc/opshaven/read-only.json"]);
  assert.equal(payload.originalCommand, null, "reset environment must remove SSH_ORIGINAL_COMMAND");
  assert.equal(payload.path, "/usr/bin:/bin");
  assert.equal(payload.home, "/nonexistent");
  assert.equal(payload.lang, "C");
  assert.equal(payload.lcAll, "C");
  assert.equal(launched.stdout.includes("uid="), false);

  const denied = run(["id"]);
  assert.equal(denied.status, 126);
  assert.match(denied.stderr, /requires --config/);
  assert.equal(denied.stdout.includes("uid="), false);

  console.log("readonly-wrapper: unprivileged launch passed and arbitrary SSH command input was denied");
} finally {
  rmSync(directory, { recursive: true, force: true });
}
