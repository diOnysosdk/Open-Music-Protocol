# OMP v0.2 W8.2 alpha-candidate report

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

