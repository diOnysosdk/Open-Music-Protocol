# OMP v0.2 external alpha readiness

## W8.5 usability and packaging

The reference CLI now provides subcommand help, version output, stricter option
diagnostics, and black-box integration tests. Windows and Linux internal
candidate builders use clean output directories, verify the frozen baseline,
include public CC0 samples, SBOMs, licenses, attribution, installation and
security documents, and generate a complete `SHA256SUMS`. The independent
`scripts/verify-alpha.py` rejects unsafe, duplicate, missing, altered, and
unlisted candidate files.

This usability workstream is **GO** for integration. It does not change the
release gate: `W8-11` remains open at High severity, controlled external alpha
is **NO-GO**, and production is **NO-GO**.

## Current blocker — 2026-10-27

Hosted conformance run
[`40495623365`](https://github.com/diOnysosdk/Open-Music-Protocol/actions/runs/40495623365)
passed Windows, Ubuntu, and RustSec jobs against commit
`0cda635d767b1fb73d5c52796a175f53ff17a09a`. The matching hosted sanitizer
run
[`40495625138`](https://github.com/diOnysosdk/Open-Music-Protocol/actions/runs/40495625138)
passed four targets but failed `media_decode` with an unresolved FLAC
memory-exhaustion finding. Therefore:

- Controlled development: **GO**, excluding reliance on the affected decoder
  for adversarial media.
- Controlled external alpha: **NO-GO** pending media-decoder remediation and a
  green five-target ASan rerun.
- Production release: **NO-GO**, additionally pending all previously recorded
  independent assurance and platform requirements.

## W8.4 status — 2026-10-27

Workflow and frozen-baseline verification passed locally, but the workflow
changes remain uncommitted and GitHub CLI is unauthenticated. No hosted Windows,
Linux, or ASan execution evidence exists. Controlled external alpha therefore
remains **NO-GO**.

## W8.3 status — 2026-10-27

GitHub transport is available and `origin/main` matches local commit
`a384ca834578a44a35cb64760760da718798e78c`, but GitHub CLI remains
unauthenticated. No hosted Windows/Linux result or Linux sanitizer campaign is
available. A manual Linux ASan workflow and bounded media-decoder target have
been prepared and locally compile-checked, but configured or compiled checks
are not counted as execution evidence.

- Controlled development: **GO**.
- Controlled external alpha: **NO-GO** pending green hosted matrix and ASan
  run evidence for the same reviewed commit.
- Production release: **NO-GO** pending independent assurance and the existing
  production security requirements.

Label for every candidate: **OMP v0.2 — Experimental Alpha / Not Production Ready**.

GitHub CI could not be dispatched on 2026-10-26 because `gh auth status`
reported no authenticated host. Docker Linux was also unavailable. Therefore
Windows/Linux matrix success is not claimed and external alpha remains blocked
on archived green workflow runs.

Local Windows evidence: frozen hashes pass, 51 Rust tests pass, 22 Python tests
pass with one documented privilege-dependent skip, formatting/Clippy/docs pass,
fuzz targets compile, and RustSec reports zero findings across 186 locked
packages. Nightly and cargo-fuzz were installed, but the bounded libFuzzer run
could not link because the Windows LLVM AddressSanitizer runtime was missing;
this is an explicit campaign blocker, not a passing result. Two clean Windows
builds are byte-identical after enabling the MSVC `/Brepro` linker option.

## Packaging

After green CI and owner authorization, run:

```powershell
./scripts/build-alpha.ps1
```

Build Linux with `cargo build --release --locked -p omp-cli -p omp-player` in
the green Linux job. Package binaries, the CC0 demonstration package,
installation/offline-playback instructions, known limitations, licenses,
attributions, `docs/SECURITY.md`, SBOM, and `SHA256SUMS`. Do not include test
private seeds or the cryptographic fixture key file. Verify checksums on a
second machine. Detached signatures require an owner-controlled offline key;
none was created or used here.

## Gate

- Controlled development: **GO**.
- External alpha: **NO-GO until real Windows/Linux CI evidence exists**.
- Production: **NO-GO**.

