# OMP v0.2 W8.2 alpha-candidate report

## W8.5 hosted Linux candidate — 2026-10-27

Commit `9b88fb48d3a825d4773327d2817d4b221606b28f` passed Windows, Ubuntu,
RustSec, and Linux packaging in hosted run
[`40500074568`](https://github.com/diOnysosdk/Open-Music-Protocol/actions/runs/40500074568).
The retained Linux x86_64 artifact is 1,747,218 bytes with GitHub archive
digest `sha256:83af13b8890a290c99511c4d9b6ca409feb89b17ce0b989f65f721c29f115779`.
Its downloaded inventory verified 27/27 checksums and the package audit passed
28 files/eight SBOMs with no private-key documents. Primary hashes are:

- `omp`: `0f49963395233e585076b41dcf8aa4e1972319fe0322dd155f847469d18275a3`
- `omp-player`: `23ff5b4666297bc0ca376b2d3d51d64a2091a5d5fdeb43d219c4303f7c835361`
- `SHA256SUMS`: `d22df2a6fd7b1a107507bcffe259a9e31584d9c21a16dacf293cec6303ae5e20`

W8.5 packaging qualification is **PASS**. This artifact is not a release:
`W8-11` remains **OPEN/HIGH**, and external alpha and production remain
**NO-GO**.

## W8.3 qualification update — 2026-10-27

The existing internal unsigned Windows candidate remains a local assurance
artifact only. It was not rebuilt, published, tagged, or expanded with a Linux
binary because the required hosted platform and sanitizer gates have not
executed. A versioned cross-platform external-alpha candidate must be produced
from the exact commit that obtains green Windows, Linux, audit, and Linux ASan
jobs; its checksums and run URLs must then be recorded here.

Current qualification is unchanged: controlled external alpha is **NO-GO**.

> **OMP v0.2 — Experimental Alpha / Not Production Ready**

**Original candidate date:** 2026-10-26

## Candidate scope

The repository can produce an internal Windows x86_64 candidate with the CLI,
player, checksums, SBOMs, licenses, security policy, and known-limitations
documents. It is unsigned and must not be represented as authenticated.
No Linux binary is eligible for inclusion until the hosted Ubuntu job passes.
No artifact was published, tagged, uploaded, or distributed by this work.

Build locally with:

```powershell
powershell -File scripts/build-alpha.ps1
Get-Content dist/omp-v0.2-alpha-windows-x86_64/SHA256SUMS
```

Recipients must obtain `SHA256SUMS` through an independently authenticated
channel and verify with `Get-FileHash`. Detached signing remains an owner-run
procedure using an established release identity; this assessment neither
created nor used a signing key.

## Known limitations and blockers

- GitHub Windows/Linux matrix has not run for the candidate commit.
- Linux `openat`, filesystem-race, and ALSA compilation evidence is missing.
- The bounded sanitizer fuzz campaigns did not execute on this Windows host.
- Rollback-sensitive trust and trusted-time functionality requires a platform
  capability that provides authenticated, monotonic, clone-aware storage; it
  fails closed without that capability.
- Windows reparse-point behavior still requires expanded platform testing.
- Production release requires independent security and platform assurance.

## Gate recommendation

- Controlled development: **GO**.
- Controlled external alpha: **NO-GO** until hosted Windows/Linux CI and fuzz
  evidence pass for the exact candidate commit.
- Production release: **NO-GO**.

