# OMP v0.2 W8.2 reproducibility report

**Date:** 2026-10-26  
**Host:** Windows x86_64, Rust/Cargo `1.99.1` stable

Two clean, isolated release builds used `--locked` and
`SOURCE_DATE_EPOCH=1793052000`. The initial MSVC builds had equal sizes but
different hashes, demonstrating linker nondeterminism. The repository now
passes `/Brepro` to the MSVC linker through `.cargo/config.toml`.

Two further clean target directories then produced byte-identical files:

| Artifact | Size | SHA-256 |
|---|---:|---|
| `omp.exe` | 794112 | `41b7d6e5dfb273375c769f9727c72e219349b2adca702e2689d779578e6445e1` |
| `omp-player.exe` | 1987072 | `663d6ab5d0be248b77500cab49a0975121cbedde34277830a6c7ec23f7a69517` |

These hashes describe local build outputs, not published or signed releases.
They must be reproduced from the final committed tree in GitHub CI. Linux
reproducibility was not executed and remains open. Debug symbols and archive
metadata should be compared separately if later distributed.

Reproduction command (PowerShell):

```powershell
$env:SOURCE_DATE_EPOCH='1793052000'
$env:CARGO_TARGET_DIR='target-repro-one'
cargo build --release --locked -p omp-cli -p omp-player
$env:CARGO_TARGET_DIR='target-repro-two'
cargo build --release --locked -p omp-cli -p omp-player
Get-FileHash target-repro-one/release/omp*.exe -Algorithm SHA256
Get-FileHash target-repro-two/release/omp*.exe -Algorithm SHA256
```

