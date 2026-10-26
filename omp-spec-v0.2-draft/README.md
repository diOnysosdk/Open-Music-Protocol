# OMP Protocol v0.2 frozen controlled-implementation artifacts

These schemas and vectors are frozen as `OMP-v0.2-w0-freeze.1` for controlled
implementation. They are not a production-release approval. OMP v0.1 remains
unchanged and is validated only under its original signing semantics.

Draft objects use JSON Schema Draft 2020-12. Example and negative-vector
expectations are described in `test-vectors/README.md`. The positive
cryptographic vectors have been reproduced by independent Rust and Python
implementations; older schema-case placeholders remain explicitly non-crypto.

The frozen schemas cover manifests, metadata, licenses, self-certifying
identity documents, key lifecycle events, portable trust bundles, and time
anchors. Exact domains are in `docs/signing-profiles-v0.2.md`.

