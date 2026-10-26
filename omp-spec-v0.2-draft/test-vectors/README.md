# Frozen OMP v0.2 interoperability vectors

Each applicable vector contains:

- source JSON exactly as transported;
- expected RFC 8785 bytes and SHA-256;
- exact domain-separated signing bytes and SHA-256;
- signature and detached public/trust inputs;
- required local asset bytes where applicable;
- expected success or stable error code;
- an explanation of the invariant covered.

Required positive families are v0.1 regression, v0.2 manifest and metadata,
identity genesis and rotation, trust bundle, unrestricted/permanent/time-limited
licenses, and deterministic multi-asset binding.

Required negative families are duplicate JSON keys, invalid Unicode and JCS
numbers, prohibited/undeclared fields, cross-version domain
confusion, tampering, wrong/rotated/revoked keys, identity-chain fork and
rollback, stale trust, path traversal, normalization and case collisions,
duplicate binding names, asset hash/size mismatch, license boundaries, and
clock rollback/state loss.

Fixture private keys are permitted only in the test-vector source tree and
must be conspicuously labeled. They must never be embedded in production
artifacts or binaries.

`cryptographic-vectors.json` is the deterministic positive cryptographic set.
It contains real signatures and exact JCS/signing payload bytes for all six
v0.2 signing profiles. Python generates it with `rfc8785` and `cryptography`;
`crates/omp-crypto/tests/v02_vectors.rs` independently checks it using Rust
`serde_jcs` and `ed25519-dalek`. Every included private seed is public
TEST-ONLY material.

The reproducible WAV/FLAC assets and their exact hashes are under `fixtures/`.
`security-cases.json` covers the requested negative families, while
`rfc8785-edge-cases.json` records the official RFC 8785 numeric and UTF-16
ordering example exercised by the Python tests. The numeric set is the complete
RFC 8785 Appendix B table.

The frozen metadata and deterministic asset-binding cases are documented
in `METADATA-ASSET-VECTORS.md`, with cases in
`metadata-asset-cases.json` and a schema-positive example in
`manifest-metadata-multiasset.valid.json`. Its signature is a deliberate
placeholder and is not a positive cryptographic vector.

The identity and trust-bundle schema/semantic cases are represented by
`identity-document-cases.json` and `trust-bundle-cases.json`. Their base
objects pass the frozen schemas, but their placeholder proof bytes are not
asserted as valid signatures. Use `cryptographic-vectors.json` for normative
positive cryptographic cases.
