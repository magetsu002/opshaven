#!/usr/bin/env bash
set -euo pipefail
[[ -z "$(git status --porcelain)" ]] || { echo "Working tree is not clean." >&2; exit 1; }
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
npm audit --omit=dev --audit-level=high
node scripts/security-scan.mjs
integration/disposable-vps/run.sh
[[ -z "$(git status --porcelain)" ]] || { echo "Certification changed tracked files." >&2; exit 1; }
printf 'Locked install, format, lint, typecheck, tests, build, package, docs, security, MCP, and deployment lifecycle passed at %s\n' "$(git rev-parse HEAD)"
printf 'Do not create v1.0.0 until this exact tree is on main and all exact-head GitHub checks, including CodeQL, are green.\n'
