#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-artifacts}"
PUBLIC_KEY="${2:-}"
[[ -d "$DIR" && -f "$DIR/SHA256SUMS" ]] || { echo "Artifact directory or checksums are missing." >&2; exit 1; }
(cd "$DIR" && sha256sum -c SHA256SUMS)
if [[ -n "$PUBLIC_KEY" ]]; then
  [[ -f "$PUBLIC_KEY" && -f "$DIR/SHA256SUMS.sig" ]] || { echo "Artifact signature or public key is missing." >&2; exit 1; }
  openssl pkeyutl -verify -rawin -pubin -inkey "$PUBLIC_KEY" -in "$DIR/SHA256SUMS" -sigfile "$DIR/SHA256SUMS.sig" >/dev/null
  printf 'artifact signature verified\n'
fi
shopt -s nullglob
archives=("$DIR"/*.tar.gz)
sboms=("$DIR"/*.sbom.cdx.json)
provenance=("$DIR"/*.provenance.intoto.json)
[[ ${#archives[@]} -eq 1 && ${#sboms[@]} -eq 1 && ${#provenance[@]} -eq 1 ]] || { echo "Required release artifact set is incomplete." >&2; exit 1; }
printf 'release artifacts verified\n'
