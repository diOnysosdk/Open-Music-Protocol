# OMP v0.2 Rust reference APIs

All APIs are local and offline. Generated Rustdoc (`cargo doc --workspace
--no-deps`) is authoritative for signatures; this page identifies intended
integration boundaries.

| Crate | Public integration surface |
|---|---|
| `omp-core` | strict v0.1/v0.2 models, parsing, validation, version detection, and non-normative diagnostic categories |
| `omp-crypto` | JCS canonicalization, fixed signing domains, Ed25519 verification, public-key decoding, and streaming SHA-256 |
| `omp-manifest` | v0.1 manifest creation, signature verification, and exact asset verification |
| `omp-identity` | authenticated identity/lifecycle facts, trust-bundle integration, role authorization, durable-pin assessment, and playback-policy decisions |
| `omp-media` | authenticated v0.2 manifests, safe package roots, deterministic asset selection, container preflight, and verified file handles |
| `omp-license` | authenticated licenses/time anchors, trusted-time state/store boundary, entitlement evaluation, and opaque playback permits |
| `omp-player` | ordered authorization pipeline, opaque prepared playback, bounded headless decoding, and caller-selected audio sinks |
| `omp-cli` | end-user v0.1 key generation, packaging, inspection, and verification |

Compile-checked integrations live in `crates/omp-media/examples/verify_package.rs`,
`crates/omp-license/examples/evaluate_license.rs`, and
`crates/omp-identity/examples/playback_authorization.rs`.

Applications should preserve this order:

```text
parse/schema -> authenticate signature -> authorize key/role
             -> evaluate license (+ trusted time if required)
             -> verify selected media -> prepare opaque playback handle
             -> decode/play
```

Do not construct permits/prepared handles yourself. Do not treat key
possession, signature validity, public availability, or playback availability
as legal ownership. Private keys belong only in protected local signing inputs
and must never be logged, embedded, or packaged.
