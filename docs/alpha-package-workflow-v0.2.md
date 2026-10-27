# OMP v0.2 alpha package workflow

> **OMP v0.2 — Experimental Alpha / Not Production Ready**

This workflow is offline and service-neutral. It does not bypass `W8-11`; the
player remains unsuitable for untrusted media until that finding is closed.

## Create and verify a manifest

1. Build with `cargo build --release --locked -p omp-cli`.
2. Copy the CC0 WAV fixture from
   `omp-spec-v0.2-draft/fixtures/audio/omp-triangle-250ms.wav` into an empty
   working directory. Its generator and expected hashes are recorded in
   `fixture-index.json`.
3. Generate a local key with `omp keygen`. Generated private keys are local
   operator material: never add them to the package or repository.
4. Run `omp pack` with explicit IDs and `--created-at` when deterministic
   manifest bytes are needed.
5. Run `omp inspect`, then `omp verify` using the separately distributed public
   key document.

Packaging the same audio, IDs, timestamp, and signing key produces the same
signed manifest. Ordinary `keygen` intentionally uses OS randomness, so
independently generated keys do not produce byte-identical manifests.

## Play a reviewed v0.2 package

The v0.2 player requires an authenticated manifest, license, identity document,
explicit package root, and expected public key. Use `omp-player verify` before
`play-headless` or `play`. Playback does not begin before protocol, entitlement,
path, and media-integrity checks succeed. Because `W8-11` remains open, do not
use the reference player with untrusted FLAC files.

## Candidate packaging and verification

- Windows: `powershell -File scripts/build-alpha.ps1`
- Linux: `bash scripts/build-alpha.sh`
- Verify either directory: `python scripts/verify-alpha.py DIST_DIR`

The builders refuse to merge into an existing output directory, include only
public CC0 fixture data, copy SBOMs and notices, and create `SHA256SUMS`. They do
not publish, tag, or sign anything. Detached signing remains an owner-operated
step using an independently protected key.
