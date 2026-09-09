# Local agent workspaces

OpsHaven V1.2 makes a local project the normal unit of work. Remote server operations remain available, but they are no longer required to use OpsHaven for coding work.

## Start

```bash
opshaven init
opshaven workspace add ~/Projects/example
opshaven connect
```

`opshaven init` prepares local OpsHaven state. It does not ask for a remote server unless remote initialization options are supplied explicitly.

`opshaven workspace add` registers a real local directory. Interactive onboarding asks four human questions:

- Can the AI read this project?
- Can the AI edit files?
- Can the AI run project tasks such as tests and builds?
- Can the AI run broader terminal commands inside this project?

The defaults are read on, edit off, project tasks off, and broader commands off. Editing and command execution are independent permissions.

For non-interactive registration, set permissions explicitly when needed:

```bash
opshaven workspace add ~/Projects/example \
  --read on \
  --edit on \
  --tasks on \
  --commands off
```

Inspect or change the resulting state without editing configuration files:

```bash
opshaven workspace list
opshaven workspace info example
opshaven workspace permissions example
opshaven workspace permissions example --edit on --tasks on
```

Workspace state is stored privately under `~/.config/opshaven/`. Existing V1.1 remote configuration is kept separately and is not replaced when a workspace is added. Registry and manifest reads use descriptor-safe non-symlink file access rather than check-then-read paths.

## Agent tools

The local MCP catalogue provides bounded project context, editing, Git inspection, task execution, and optional command execution.

Context tools:

- `workspace_info`
- `workspace_tree`
- `list_files`
- `read_file`
- `read_files`
- `search_files`
- `file_hash`
- `code_context`
- `project_info`
- `discover_tasks`

Git tools:

- `git_status`
- `git_diff`
- `git_log`

Editing tools:

- `create_file`
- `replace_file`
- `edit_file`
- `edit_files`

Execution tools:

- `run_task`
- `run_command`

Reads, trees, searches, logs, diffs, and process output are bounded. Common generated/vendor directories are skipped during recursive context collection. Project paths remain inside the registered workspace and symlink traversal is rejected.

`replace_file`, `edit_file`, and `edit_files` use the SHA-256 file identity returned by read/hash operations. If the file changed after the agent read it, the edit reports a conflict instead of overwriting newer content. `create_file` uses exclusive creation so it cannot overwrite a file that appeared concurrently.

## Project tasks and verification evidence

`discover_tasks` derives commands from project metadata rather than inventing them. V1.3 preserves every project-defined task while ranking it as primary verification, development, advanced/maintenance, or other. Recognized task sources include:

- npm, pnpm, and yarn scripts declared in `package.json`;
- `cargo check` and `cargo test` for Cargo projects;
- `pytest` when Python project metadata indicates pytest;
- `go test ./...` for Go modules.

Primary verification favors tests, type checking, linting, and the project build. Development tasks such as `dev` and `start` remain discoverable, while release, security, certification, integration, installation, and similar maintenance tasks remain available without being presented as equivalent day-to-day verification.

`run_task` requires the workspace's project-task permission. Each Git-backed task run records whether the exact pre-run source state remained unchanged and whether the task passed. Evidence is bound to the complete `HEAD` commit plus a digest of the working-tree status, so evidence becomes stale when either the commit or working tree changes. `run_command` remains separate and requires broader command execution to be enabled. Both use argv-based subprocess execution without a shell.

Broader command execution is deliberately not an arbitrary executable-path primitive. V1.2 accepts these developer command names:

```text
node npm npx pnpm yarn git python python3 pytest cargo rustc go make cmake ninja
```

Absolute executable paths are denied except for the currently running Node executable, which is normalized to `node`. Shell launchers and direct privilege-escalation commands are not in the supported command set. RPC-supplied command arguments use a narrow non-shell character grammar. Process timeouts are selected from fixed bounded values of 1, 5, 30, 120, or 600 seconds.

Child processes receive only a minimal environment: `PATH`, `LANG`, `LC_ALL`, and, when present, `HOME` and `TMPDIR`. Arbitrary operator environment variables and secrets are not inherited by project tasks or broader commands.

Project tasks may themselves execute commands declared by the project's own build metadata. That is why task execution remains a separate permission from read/edit access.

## Source-to-runtime continuity

V1.3 adds four structured agent operations without replacing the existing bounded tools:

- `project_state` returns the exact local revision, dirty/clean state, ranked tasks, and verification evidence current for that source state.
- `verify_workspace` runs only discovered primary verification tasks and records their exact source-bound outcomes.
- `source_runtime_state` joins one workspace to one registered deployment application and reports local revision, deployed revision, service/health state, rollback state, and Git ancestry relationship.
- `prepare_verified_deployment` prepares the existing immutable deployment plan only when the workspace is clean, `HEAD` is a committed exact revision, and every discovered primary verification task has current passing evidence.

These operations do not commit files, invent deployment commands, or bypass V1.1 deployment authorization. A dirty working tree remains distinct from `HEAD`, and deployment planning still re-verifies the target revision through the configured application source before producing an exact plan.

## MCP connection

For local MCP clients that support stdio, run:

```text
command: opshaven-mcp
transport: stdio
```

No remote OpsHaven configuration is required for local workspaces. If valid remote configuration is already present, the same MCP process can continue to expose the mature remote operation tools alongside the local workspace catalogue.

Run `opshaven connect` to print the current connection guidance.

### ChatGPT

ChatGPT does not connect directly to a localhost MCP server. OpenAI's current guidance for MCP running on a private network, on-premises environment, or developer machine is to use Secure MCP Tunnel rather than exposing the local server to the public internet.

Full MCP write/modify support and account-plan availability are controlled by ChatGPT and may differ from local MCP clients. OpsHaven therefore reports the transport requirement without pretending that a localhost URL is directly usable by ChatGPT.

## Engineering loop

The intended agent workflow is:

```text
inspect project
→ find relevant code
→ inspect Git state
→ read context
→ edit with current file identity
→ inspect diff
→ discover verification tasks
→ run verification
→ inspect failure output
→ revise
→ rerun verification
→ compare exact local revision with configured environment
→ prepare immutable deployment plan from verified committed HEAD
→ apply through the existing deployment path when explicitly approved
→ verify health and retain rollback evidence
→ report result
```

Repository integration tests use synthetic temporary projects owned by the OpsHaven test suite. They do not inspect unrelated personal repositories.
