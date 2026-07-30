#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${OPSHAVEN_ARTIFACT_DIR:-artifacts}"
SIGNING_KEY="${1:-}"
[[ -z "$(git status --porcelain)" ]] || { echo "Working tree must be clean." >&2; exit 1; }
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
export TZ=UTC
export LC_ALL=C

rm -rf "$OUT"
install -d -m 700 "$OUT"
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
node scripts/verify-lockfile.mjs

VERSION="$(node -p 'require("./package.json").version')"
ARCHIVE="$OUT/opshaven-${VERSION}.tar.gz"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --pax-option=delete=atime,delete=ctime -czf "$ARCHIVE" dist dist-readonly package.json package-lock.json README.md LICENSE SECURITY.md docs packaging security/capability-declaration.json
node scripts/generate-sbom.mjs "$OUT/opshaven-${VERSION}.sbom.cdx.json"
PROVENANCE_OUTPUT="$OUT/opshaven-${VERSION}.provenance.intoto.json" node scripts/generate-provenance.mjs "$ARCHIVE" "$OUT/opshaven-${VERSION}.sbom.cdx.json"
(
  cd "$OUT"
  sha256sum "$(basename "$ARCHIVE")" "opshaven-${VERSION}.sbom.cdx.json" "opshaven-${VERSION}.provenance.intoto.json" > SHA256SUMS
)
if [[ -n "$SIGNING_KEY" ]]; then
  [[ -f "$SIGNING_KEY" ]] || { echo "Release signing key does not exist." >&2; exit 1; }
  openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY" -in "$OUT/SHA256SUMS" -out "$OUT/SHA256SUMS.sig"
  openssl pkey -in "$SIGNING_KEY" -pubout -out "$OUT/release-public.pem" >/dev/null
  scripts/verify-release-artifacts.sh "$OUT" "$OUT/release-public.pem"
else
  (cd "$OUT" && sha256sum -c SHA256SUMS)
fi
printf 'verifiable release artifacts created at %s for %s\n' "$OUT" "$(git rev-parse HEAD)"
