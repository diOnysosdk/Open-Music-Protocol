# OMP v0.2 external alpha readiness

## W8.5 packaging qualification closure — 2026-10-27

W8.5 packaging qualification is **PASS** for commit
`9b88fb48d3a825d4773327d2817d4b221606b28f`. Local `main` and `origin/main`
matched that commit before qualification. Hosted GitHub Actions run
[`40500074568`](https://github.com/diOnysosdk/Open-Music-Protocol/actions/runs/40500074568)
completed successfully: Windows test, Ubuntu test, RustSec audit, and Linux
packaging jobs each concluded `success`.

The hosted artifact
`omp-v0.2-alpha-linux-x86_64-9b88fb48d3a825d4773327d2817d4b221606b28f`
was 1,747,218 bytes; GitHub recorded archive digest
`sha256:83af13b8890a290c99511c4d9b6ca409feb89b17ce0b989f65f721c29f115779`.
After download, all 27 entries in `SHA256SUMS` verified. Independent audit
covered 28 files, found eight SBOMs, and found no private-key documents. The
Linux executables were `omp` (1,229,944 bytes,
`0f49963395233e585076b41dcf8aa4e1972319fe0322dd155f847469d18275a3`)
and `omp-player` (2,715,512 bytes,
`23ff5b4666297bc0ca376b2d3d51d64a2091a5d5fdeb43d219c4303f7c835361`).

This closes only W8.5 usability/packaging qualification. `W8-11` remains
**OPEN/HIGH**. External alpha and production release remain **NO-GO**.

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

