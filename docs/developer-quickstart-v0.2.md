# OMP v0.2 developer quickstart

OMP is an offline-first Rust reference implementation. Nothing in this guide
contacts a registry, identity provider, license server, blockchain, or other
central service. The v0.2 protocol and its 42-artifact baseline are frozen.

## Prerequisites and builds

Use Rust 1.75 or newer (stable, with Cargo, rustfmt, and Clippy) and Python 3.12
or newer. Python conformance dependencies are `pytest`, `jsonschema`, `rfc8785`,
`cryptography`, and `soundfile`. Builds use the committed `Cargo.lock`.

Windows (PowerShell, Visual Studio Build Tools/MSVC installed):

```powershell
rustup toolchain install stable --component rustfmt,clippy
python -m pip install pytest jsonschema rfc8785 cryptography soundfile
cargo build --locked --workspace
cargo test --locked --workspace
python scripts/conformance.py
```

Ubuntu/Debian Linux:

```sh
sudo apt-get update && sudo apt-get install -y build-essential pkg-config libasound2-dev libsndfile1 python3-pip
rustup toolchain install stable --component rustfmt,clippy
python3 -m pip install pytest jsonschema rfc8785 cryptography soundfile
cargo build --locked --workspace
cargo test --locked --workspace
python3 scripts/conformance.py
```

## Complete offline lifecycle

1. Generate and protect a local signing key with `omp keygen`. Share only the
   public document. Never place the private document in a package or example.
2. Bind exact audio bytes into a signed v0.1 manifest with `omp pack`.
3. Inspect structure with `omp inspect`; this deliberately does not establish
   signer trust.
4. Authenticate the signature and exact audio bytes with `omp verify`, using a
   public key obtained through the integrator's trust process.
5. For v0.2, separately validate identity history and key-role authorization,
   authenticate the manifest and license, evaluate the license with trusted
   time when required, then permit playback only from the opaque prepared
   handle. No ordinary wall clock is accepted for time-limited grants.
6. Persist trust pins and time checkpoints only in authenticated,
   rollback-resistant platform storage. Fail closed if unavailable.

Run the deterministic public-domain examples from the repository root:

```text
cargo run --locked -p omp-media --example verify_package
cargo run --locked -p omp-license --example evaluate_license
cargo run --locked -p omp-identity --example playback_authorization
```

They consume the frozen CC0 fixtures and public keys only. The first proves
package authentication/media binding, the second evaluates an entitlement,
and the third makes a playback-availability decision. Those are intentionally
separate boundaries; a valid signature is not authorization or a license.

## Conformance and diagnostics

`python scripts/conformance.py` runs the existing v0.1/v0.2 fixture suites and
writes `target/conformance/report.json` plus `report.txt`. Each record includes
the pytest node identifier, `PASSED`, `FAILED`, or `SKIPPED`, and diagnostics.
Frozen fixtures are read, never repaired or regenerated.

CLI failures begin with a stable, non-normative diagnostic category and an
action. Categories are `OMP-DIAG-USAGE`, `OMP-DIAG-MALFORMED-CONTENT`,
`OMP-DIAG-INVALID-SIGNATURE`, `OMP-DIAG-UNAUTHORIZED-KEY`,
`OMP-DIAG-INVALID-LICENSE`, `OMP-DIAG-UNTRUSTED-TIME`, and
`OMP-DIAG-OPERATIONAL`. The original protocol error remains in the message;
categories do not change frozen error semantics.

## ARM64 preparation

ARM64 is experimental and unqualified. On a Raspberry Pi 400 or another real
64-bit ARM Linux host, install the prerequisites above, confirm `uname -m`
reports `aarch64`, and run `sh scripts/validate-arm64.sh`. Archive the exact
commit, OS/kernel, `rustc -Vv`, results, and report files. Cross-compilation or
emulation is useful preparation but is not compatibility evidence. Audio
device tests, filesystem behavior, resource limits, and all frozen fixtures
must pass on actual hardware before any ARM64 support claim.

`W8-11` remains an **OPEN/HIGH** FLAC decoder blocker. Do not use these
developer tools as evidence that external alpha or production is approved.
