#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"

resolve_command() {
  command -v "$1"
}

assert_installed_command() {
  local command_name="$1"
  local expected_target="$2"
  local command_path
  command_path="$(resolve_command "$command_name")"
  test -n "$command_path"
  test -x "$command_path"
  local resolved_command
  local resolved_target
  resolved_command="$(node -e 'const fs=require("node:fs"); console.log(fs.realpathSync(process.argv[1]))' "$command_path")"
  resolved_target="$(node -e 'const fs=require("node:fs"); console.log(fs.realpathSync(process.argv[1]))' "$expected_target")"
  if [[ "$resolved_command" != "$resolved_target" ]]; then
    printf '%s resolved to an unexpected target\n' "$command_name" >&2
    exit 1
  fi
}

npm run install:local
hash -r
assert_installed_command opshaven "$repository_root/dist/src/cli-entry.js"
assert_installed_command opshaven-mcp "$repository_root/dist/src/mcp-entry.js"
opshaven --version | grep -Eq '^OpsHaven 1\.0\.0$'
opshaven-mcp --version | grep -Eq '^OpsHaven MCP 1\.0\.0$'

npm run build
hash -r
assert_installed_command opshaven "$repository_root/dist/src/cli-entry.js"
assert_installed_command opshaven-mcp "$repository_root/dist/src/mcp-entry.js"
opshaven --version | grep -Eq '^OpsHaven 1\.0\.0$'
opshaven-mcp --version | grep -Eq '^OpsHaven MCP 1\.0\.0$'

printf 'installed CLI: link, executable mode, version, and rebuild lifecycle verified\n'
