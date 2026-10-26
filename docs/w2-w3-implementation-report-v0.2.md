# OMP v0.2 W2/W3 implementation report

Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1` plus ADR-013 amendment  
Recommendation: **CONDITIONAL GO**.

> ADR-014 subsequently resolved the trust-bundle vector disposition. See
> `docs/w4-trust-bundle-integration-report-v0.2.md` for the completed boundary
> and current controlled-integration recommendation.

## Implemented

### W2 — `omp-core::v02`

- duplicate-safe exact version detection with no model fallback;
- strict closed Rust models for manifests, metadata, identity documents, key
  lifecycle events, licenses, trust bundles, and time anchors;
- schema-equivalent field, encoding, cardinality, identifier, timestamp, and
  cross-field validation;
- NFC metadata/path rejection, closed contributor roles, deterministic asset
  uniqueness, exactly one primary asset, portable-path rules, license policy,
  threshold shape, and chain-link shape checks;
- explicit v0.1/v0.2 dispatch boundary preserving the existing v0.1 parser.

### W3 — `omp-crypto`

- typed `V02Profile` for all six frozen signing domains;
- exact profile-owned top-level member exclusion;
- RFC 8785 signing payload generation with no fallback;
- strict Ed25519 sign/verify APIs and unpadded base64url handling;
- self-certifying identity commitment API;
- canonical complete-object SHA-256 API;
- independent verification of every published v0.2 cryptographic vector.

### W4 integration

`ProductionFactProvider` is the concrete authenticated adapter. It parses via
W2, authenticates via W3, recomputes commitments and complete hashes, and then
constructs W4 validated facts. Tampered objects and role-unauthorized bundle
signers do not cross the boundary.

## Public APIs

- `omp_core::v02::detect_version`, `parse`, `WireVersion` and the seven frozen
  model families.
- `omp_crypto::V02Profile`, `v02_signing_bytes`, `verify_v02`, `sign_v02`,
  `v02_identity_id`, and `canonical_object_sha256`.
- `omp_identity::ProductionFactProvider` implementing
  `ValidatedFactProvider`.

Private signing keys remain caller-owned and are never represented in wire
models, manifests, licenses, or trust bundles.

## Frozen-vector inconsistency

The published trust-bundle cryptographic vector has a valid `root-01`
signature. Its embedded identity grants role `trust-bundle` only to operational
key `media-01`; recovery key `root-01` has no operational role field. Therefore:

- W3 correctly verifies the published signature as a cryptographic vector.
- The W4 integration boundary correctly rejects it as an authorized portable
  trust bundle.
- A test-only copy signed by `media-01` passes the complete W2/W3/W4 boundary.

The frozen vector cannot be changed in place. Protocol owners must either
publish a separately versioned corrected authorized-bundle vector or explicitly
amend trust-bundle signer authorization. The implementation does not infer
recovery-key publishing authority.

## Security limitations

- JSON Schema parity is implemented manually and requires independent review
  and continued differential tests against the authoritative schemas.
- W3 authenticates bytes and key control; W4 role checks establish protocol
  authorization. Neither establishes legal identity or ownership.
- Identity/lifecycle chain semantics and platform persistence retain the W4
  assurance limitations already recorded.
- No production secret-storage abstraction is introduced by W2/W3; callers
  retain responsibility for private-key protection.

## Remaining blockers

- Protocol-owner disposition or separately versioned replacement for the
  role-unauthorized trust-bundle vector.
- Independent schema-parity, cryptographic-profile, and cross-crate adapter
  review before release.
- Production W4 secure-storage implementations and platform assurance.

W2 and W3 production APIs are ready for controlled integration. W4 identity
and lifecycle integration is operational; portable trust-bundle conformance
remains conditional on resolution of the frozen-vector authorization mismatch.
