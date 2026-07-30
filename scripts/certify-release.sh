#!/usr/bin/env bash
set -euo pipefail
[[ -z "$(git status --porcelain)" ]] || { echo "Working tree is not clean." >&2; exit 1; }
npm ci --ignore-scripts --no-audit --no-fund
npm run check
node scripts/security-scan.mjs
integration/disposable-vps/run.sh
[[ -z "$(git status --porcelain)" ]] || { echo "Certification changed tracked files." >&2; exit 1; }
printf 'Clean install, compiled MCP startup, full checks, security scan, and disposable-VPS certification passed at %s\n' "$(git rev-parse HEAD)"
printf 'Do not create v1.0.0 until this exact head is on main, the repository is public, and exact-head GitHub CI is green.\n'
