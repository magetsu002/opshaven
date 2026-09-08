import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { WorkspaceToolExecutor } from "../src/workspace-tools.js";
import { WorkspaceStore } from "../src/workspace.js";

async function command(argv: string[], cwd: string): Promise<void> {
  const child = spawn(argv[0] as string, argv.slice(1), { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
  const result = await new Promise<{ code: number | null; stderr: string }>((resolve, reject) => {
    let stderr = "";
    child.stderr.on("data", (chunk: Uint8Array) => { stderr += Buffer.from(chunk).toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code: number | null) => resolve({ code, stderr }));
  });
  if (result.code !== 0) throw new Error(`fixture command failed: ${argv.join(" ")}\n${result.stderr}`);
}

function data(result: Awaited<ReturnType<WorkspaceToolExecutor["execute"]>>): Record<string, any> {
  assert.equal(result.ok, true, result.error?.message);
  return result.data as Record<string, any>;
}

async function fixture(): Promise<{ root: string; state: string; store: WorkspaceStore; executor: WorkspaceToolExecutor; id: string }> {
  const root = await fs.mkdtemp(path.join(tmpdir(), "opshaven-agent-loop-"));
  const state = await fs.mkdtemp(path.join(tmpdir(), "opshaven-agent-state-"));
  await fs.mkdir(path.join(root, "src"));
  await fs.writeFile(path.join(root, "package.json"), `${JSON.stringify({ name: "agent-loop-fixture", scripts: { test: "node test.mjs" } }, null, 2)}\n`);
  await fs.writeFile(path.join(root, "src", "math.mjs"), "export function add(a, b) { return a - b; }\n");
  await fs.writeFile(path.join(root, "test.mjs"), "import { add } from './src/math.mjs';\nif (add(2, 1) !== 3) { console.error('expected add(2, 1) to equal 3'); process.exit(1); }\n");
  await command(["git", "init", "-q"], root);
  await command(["git", "add", "."], root);
  await command(["git", "-c", "user.name=OpsHaven Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture baseline"], root);
  const store = new WorkspaceStore(state);
  const registered = await store.register(root, { name: "fixture", permissions: { read: true, edit: true, tasks: true, commands: false } });
  return { root, state, store, executor: new WorkspaceToolExecutor(store), id: registered.id };
}

async function cleanup(value: { root: string; state: string }): Promise<void> {
  await Promise.all([fs.rm(value.root, { recursive: true, force: true }), fs.rm(value.state, { recursive: true, force: true })]);
}

test("workspace registry rejects duplicate and symlink roots while preserving simple permissions", async () => {
  const value = await fixture();
  try {
    const record = await value.store.get(value.id);
    assert.deepEqual(record.permissions, { read: true, edit: true, tasks: true, commands: false });
    await assert.rejects(value.store.register(value.root), /already registered/);
    const link = `${value.root}-link`;
    await fs.symlink(value.root, link, "dir");
    try { await assert.rejects(value.store.register(link), /symlink/); }
    finally { await fs.rm(link, { force: true }); }
  } finally { await cleanup(value); }
});

test("agent engineering loop can inspect failure, edit with a hash, inspect diff, and rerun verification", async () => {
  const value = await fixture();
  try {
    const discovered = data(await value.executor.execute("discover_tasks", { workspaceId: value.id }));
    assert.equal(discovered.tasks.some((task: any) => task.id === "npm:test"), true);

    const failing = data(await value.executor.execute("run_task", { workspaceId: value.id, taskId: "npm:test", timeoutMs: 30_000 }));
    assert.equal(failing.exitCode, 1);
    assert.match(failing.stderr, /expected add/);

    const context = data(await value.executor.execute("read_file", { workspaceId: value.id, path: "src/math.mjs" }));
    assert.match(context.content, /a - b/);
    assert.match(context.hash, /^[a-f0-9]{64}$/);

    const edited = data(await value.executor.execute("edit_file", {
      workspaceId: value.id,
      path: "src/math.mjs",
      oldText: "return a - b;",
      newText: "return a + b;",
      expectedHash: context.hash,
    }));
    assert.notEqual(edited.hash, context.hash);

    const conflict = await value.executor.execute("edit_file", {
      workspaceId: value.id,
      path: "src/math.mjs",
      oldText: "return a + b;",
      newText: "return a * b;",
      expectedHash: context.hash,
    });
    assert.equal(conflict.ok, false);
    assert.equal(conflict.error?.details?.conflict, true);

    const diff = data(await value.executor.execute("git_diff", { workspaceId: value.id }));
    assert.match(diff.diff, /return a \+ b/);
    assert.match(diff.diff, /return a - b/);

    const passing = data(await value.executor.execute("run_task", { workspaceId: value.id, taskId: "npm:test", timeoutMs: 30_000 }));
    assert.equal(passing.exitCode, 0);

    const commandDenied = await value.executor.execute("run_command", { workspaceId: value.id, argv: ["node", "--version"] });
    assert.equal(commandDenied.ok, false);
    assert.equal(commandDenied.error?.code, "POLICY_DENIED");
  } finally { await cleanup(value); }
});

test("broader command execution is separate from editing and blocks privilege escalation", async () => {
  const value = await fixture();
  try {
    await value.store.updatePermissions(value.id, { commands: true });
    const version = data(await value.executor.execute("run_command", { workspaceId: value.id, argv: [process.execPath, "--version"] }));
    assert.equal(version.exitCode, 0);
    assert.match(version.stdout, /^v\d+/);
    const denied = await value.executor.execute("run_command", { workspaceId: value.id, argv: ["sudo", "id"] });
    assert.equal(denied.ok, false);
    assert.equal(denied.error?.code, "POLICY_DENIED");
  } finally { await cleanup(value); }
});
