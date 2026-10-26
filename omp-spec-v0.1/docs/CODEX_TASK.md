# Codex implementation task — OMP v0.1

Implement a Rust workspace with `omp-core` (types/schema validation), `omp-crypto` (RFC 8785 canonicalization + Ed25519 verification), and `omp-manifest` (asset hash verification), plus a CLI: `omp verify <manifest.json> <audio-file> --public-key <key.json>`.

Do not create a token or a blockchain; do not fabricate DRM. Preserve external JSON contracts; provide tests and documented build commands.

First implement `verify` for fixture signature and negative cases; then a `package` command that generates a signed sidecar manifest from real local audio; then `inspect`. Use secure OS key storage / external keys for real operations. Fixture private key is for tests only and MUST never be bundled in production.

Quality gate: cargo fmt, cargo clippy -D warnings, cargo test, deterministic test vectors, reject duplicate JSON keys, cross-platform Windows/Linux.

Resolve explicit TODOs in SPECIFICATION.md before calling the implementation production ready.
