# OMP v0.2 experimental alpha installation

> **OMP v0.2 — Experimental Alpha / Not Production Ready**

1. Obtain the archive and `SHA256SUMS` through authenticated channels.
2. Compare every file hash before execution (`Get-FileHash -Algorithm SHA256`).
3. Keep the executable and the entire sample directory on a local filesystem.
4. Use `omp.exe --help` and `omp-player.exe --help` for the exact command set.
5. Use headless playback for deterministic checks where no sound device exists.

Playback and verification are offline. Do not bypass a failed signature,
license, trusted-time, trust-store, pathname, or asset-integrity check. The
sample audio is CC0 test material; it is not evidence of rights to other media.

The Windows archive is unsigned unless accompanied by a separately verified
owner signature. Linux is not packaged until its hosted build and tests pass.
Report security issues using `SECURITY.md`; do not place secrets in a report.

