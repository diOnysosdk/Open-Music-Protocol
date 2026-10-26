# OMP Protocol v0.2 draft artifacts

These schemas and vectors are proposals for review. They are not approved or
production-ready. The authoritative protocol remains `omp-spec-v0.1` until a
v0.2 specification is explicitly approved.

Draft objects use JSON Schema Draft 2020-12. Example and negative-vector
expectations are described in `test-vectors/README.md`. The positive
cryptographic vectors have been reproduced by independent Rust and Python
implementations; older schema-case placeholders remain explicitly non-crypto.

Current draft schemas cover manifests, metadata, licenses, self-certifying
identity documents, key lifecycle events, portable trust bundles, and time
anchors. Exact domains are in `docs/signing-profiles-v0.2.md`.

