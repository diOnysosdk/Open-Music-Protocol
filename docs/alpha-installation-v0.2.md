# OMP v0.2 experimental alpha installation

> **OMP v0.2 — Experimental Alpha / Not Production Ready**

No release is currently approved. `W8-11`, a high-severity FLAC decoder
memory-exhaustion finding, keeps external alpha and production at **NO-GO**.
These instructions describe internal candidate verification only.

## Windows

1. Extract the candidate into a new user-owned directory.
2. Run `python scripts/verify-alpha.py PATH_TO_DIRECTORY`, or verify individual
   files with `Get-FileHash -Algorithm SHA256` against `SHA256SUMS`.
3. Run `.\omp.exe --help` and `.\omp-player.exe` from PowerShell. No installer,
   PATH mutation, service, or network access is required.
4. Windows binaries are unsigned unless an independently authenticated owner
   signature explicitly accompanies the candidate.

## Linux

1. Extract into a new user-owned directory and run
   `python3 scripts/verify-alpha.py PATH_TO_DIRECTORY`.
2. Mark binaries executable if archive transport removed mode bits:
   `chmod 0755 omp omp-player`.
3. Run `./omp --help`. Real-device playback requires the platform ALSA runtime;
   `play-headless` does not require audio hardware.

## Offline safety

Keep the executable and complete package on a local filesystem. Do not bypass
a failed signature, license, trusted-time, trust-store, path, or integrity
check. Samples are deterministic CC0 test material and convey no rights to
other media. Never place private keys inside an OMP package.

Report security issues through [SECURITY.md](SECURITY.md), without attaching
secrets or private keys. See [the package workflow](alpha-package-workflow-v0.2.md)
for manifest creation and verification.
