# OMP v0.2 W8.2 fuzz results

**Date:** 2026-10-26

## Targets

The cargo-fuzz package contains bounded-entry targets for duplicate-safe v0.2
JSON parsing, RFC 8785 canonicalization, identity and license parsing, trusted
time and lifecycle inputs, portable paths, and signature/key envelopes:

- `json_v02`
- `canonicalization`
- `identity_license`
- `path_and_envelope`

All four targets compile under an ordinary `cargo check` of the fuzz package.

## Campaign execution

Rust nightly `1.101.0-nightly (76456a688 2026-10-25)` and cargo-fuzz `0.13.2`
were installed. The attempted command was:

```powershell
cargo +nightly fuzz run json_v02 -- -max_total_time=15 -print_final_stats=1
```

The Windows MSVC link failed before execution because
`clang_rt.asan_dynamic_runtime_thunk-x86_64.lib` was unavailable. Consequently
there are no honest execution, corpus, coverage, or crash counts to report.
This is an unavailable sanitizer runtime, not a passing fuzz campaign.

## Reproduction on a supported Linux runner

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
for target in json_v02 canonicalization identity_license path_and_envelope; do
  cargo +nightly fuzz run "$target" -- -max_total_time=300 -print_final_stats=1
done
```

Archive each console log and `fuzz/artifacts/` directory. Any confirmed crash
must become a deterministic regression test before the alpha gate is reopened.

