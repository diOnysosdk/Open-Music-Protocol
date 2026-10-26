# OMP v0.2 W8.2 supply-chain results

**Date:** 2026-10-26

## Executed checks

- `cargo audit 0.22.2`: 186 locked packages checked against 1,378 advisories;
  zero vulnerabilities and zero warnings reported.
- `cargo cyclonedx 0.5.9`: CycloneDX 1.5 JSON SBOM generated for each of the
  eight workspace crates as `<crate>/<crate>.cdx.json`.
- `cargo license 0.7.0`: 186 package license expressions inventoried. Observed
  families are Apache-2.0, MIT, BSD, ISC, MPL-2.0, Unicode-3.0, Zlib,
  Unlicense, and permissive `OR` expressions. Final distribution review must
  retain notices and satisfy the selected option for every expression.
- Gitleaks `8.30.1`: repository-history scan covered four commits and about
  948 kB; no leaks were reported. Known deterministic private seeds remain
  confined to specification vectors, generators, and tests and must not be
  included in distributed packages.

No result is a legal opinion. SBOM generation and an advisory scan do not
replace provenance review, signature verification of release inputs, or an
independent security assessment.

## Generated SBOM paths

`crates/omp-{cli,core,crypto,identity,license,manifest,media,player}/*.cdx.json`

## Remaining evidence

The hosted CI must regenerate and archive the SBOMs, audit output, complete
license inventory, and secret-scan log for the exact candidate commit. A final
third-party notices file must be reviewed before distribution.

