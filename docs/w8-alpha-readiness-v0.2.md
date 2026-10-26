# OMP v0.2 external alpha readiness

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

