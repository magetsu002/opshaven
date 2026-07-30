# Reproducible and verifiable releases

OpsHaven release tags must be annotated and cryptographically signed. The tag must point to the exact commit whose CI, Security, CodeQL, restricted-SSH lifecycle, boundary verification, and reproducible build checks passed. Never move an existing release tag.

## Reproduce a build

Use Linux, Node.js 22, npm from that Node distribution, GNU tar, OpenSSL, and the committed lockfile:

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
npm ci --ignore-scripts --no-audit --no-fund
scripts/prepare-verifiable-release.sh
```

The script uses sorted archive entries, fixed timestamps, numeric ownership, UTC, the committed lockfile, and the exact checked-out tree. It produces a deterministic archive, CycloneDX SBOM, in-toto/SLSA-style provenance statement, and SHA-256 checksums. Run the build twice in clean disposable checkouts and compare `SHA256SUMS`.

## Sign and verify artifacts

Use a dedicated offline Ed25519 release key, separate from SSH, approval, capability, and response-signing keys:

```bash
scripts/prepare-verifiable-release.sh /protected/path/release-private.pem
scripts/verify-release-artifacts.sh artifacts artifacts/release-public.pem
```

The private key must not be committed or stored in build logs. The future tag workflow requires an Actions secret named `OPSHAVEN_RELEASE_SIGNING_KEY`; absence of that secret fails closed. The workflow verifies the annotated tag through GitHub's signature verification API before building.

Consumers should verify the signed tag, checksum signature, artifact checksums, SBOM, provenance source commit and tree, lockfile hash, and capability-declaration hash. These checks prove artifact identity and build inputs; they do not prove that the code is free of vulnerabilities or that the operator host is uncompromised.
