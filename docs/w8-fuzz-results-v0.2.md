# OMP v0.2 W8.2 fuzz results

## W8.4 execution gate — 2026-10-27

Locked local compilation of all five fuzz binaries passed. The GitHub Linux
ASan campaign did not execute because GitHub authentication and an authorized
commit/push are still absent. There are no run IDs, campaign counts, sanitizer
conclusions, or archived corpora to report; compilation is not treated as a
passing campaign.

## W8.3 update — 2026-10-27

The dedicated, manually dispatchable Linux workflow
`.github/workflows/fuzz.yml` now runs nightly Rust and cargo-fuzz with explicit
AddressSanitizer instrumentation. Each campaign is bounded to 30–900 seconds,
uses `set -o pipefail`, and uploads logs, corpus files, crash artifacts,
toolchain details, and a SHA-256 evidence manifest even after failure.

A fifth target, `media_decode`, exercises bounded WAV and FLAC probing and
decoding with an 8 MiB input ceiling, 256-packet ceiling, and two-million-frame
ceiling. The existing `identity_license` target covers identity documents,
lifecycle events, licenses, time anchors, and authenticated identity facts.

All five targets compile locally. The workflow parsed successfully as YAML,
and cargo-fuzz `0.13.2` confirmed the command-line options used. The Linux
workflow has **not executed** because GitHub authentication is unavailable.
No execution count, duration, corpus growth, crash count, or sanitizer result
is claimed. The external-alpha fuzz gate remains open.

**Date:** 2026-10-26

## Targets

The cargo-fuzz package contains bounded-entry targets for duplicate-safe v0.2
JSON parsing, RFC 8785 canonicalization, identity and license parsing, trusted
time and lifecycle inputs, portable paths, and signature/key envelopes:

- `json_v02`
- `canonicalization`
- `identity_license`
- `path_and_envelope`
- `media_decode`

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
for target in json_v02 canonicalization identity_license path_and_envelope media_decode; do
  cargo +nightly fuzz run "$target" -- -max_total_time=300 -print_final_stats=1
done
```

Archive each console log and `fuzz/artifacts/` directory. Any confirmed crash
must become a deterministic regression test before the alpha gate is reopened.

