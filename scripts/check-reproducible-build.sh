#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
for name in first second; do
  git clone --quiet --local --no-hardlinks "$ROOT" "$TMP/$name"
  (
    cd "$TMP/$name"
    export OPSHAVEN_ARTIFACT_DIR=artifacts
    scripts/prepare-verifiable-release.sh
  )
done
cmp "$TMP/first/artifacts/SHA256SUMS" "$TMP/second/artifacts/SHA256SUMS"
for file in "$TMP/first/artifacts"/*; do
  other="$TMP/second/artifacts/$(basename "$file")"
  [[ -f "$other" ]] || { echo "Reproducible build output is missing $(basename "$file")." >&2; exit 1; }
  cmp "$file" "$other"
done
printf 'reproducible build: two clean local clones produced identical artifacts\n'
