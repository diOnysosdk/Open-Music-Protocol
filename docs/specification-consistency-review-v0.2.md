# OMP v0.2 specification consistency review

Date: 2026-10-26  
Verdict: **superseded by the controlled-implementation readiness review**.

This report records the earlier signing-profile review. The policy decisions,
fixtures, current blockers, and recommendation are updated in
`docs/implementation-readiness-report-v0.2.md` and ADRs 007-012.

## Reviewed sources

- authoritative v0.1 specification, schemas, examples, and contract tests;
- all six v0.2 ADRs and seven Draft 2020-12 schemas;
- signing profiles, error codes, contributor vocabulary, and architecture;
- structural, semantic-case, and deterministic cryptographic vectors;
- independent Rust and Python canonicalization/signature checks.

## Finalized design decisions

1. Existing v0.1 bytes, dispatch, signature domain, and validation semantics are frozen.
2. v0.2 uses self-certifying `omp:party:sha256-<hex>` identities derived from the domain-separated JCS genesis commitment. This proves key control, not legal identity, ownership, or licensing authority.
3. Single-key control is threshold one. Recovery thresholds are optional; 2-of-3 distinct recovery keys are the recommended initial profile, not a validity requirement.
4. Manifests, identity documents, key lifecycle events, licenses, trust bundles, and time anchors have distinct domains with no fallback.
5. Revocation never deletes or makes a historical signature cryptographically false. Verification exposes historical authenticity separately from current trust.
6. TOFU produces explicit `UNVERIFIED` state. Re-observation does not promote it.
7. Trust bundles are signed portable data with no privileged transport or publisher.
8. Portable paths are NFC, relative, `/` separated, root-contained, and case-sensitive. Absolute paths, traversal, ambiguous encoding, and every symlink/reparse traversal are rejected.
9. Applicable metadata is NFC and contributors name the closed `omp-contributor-roles-v0.2` vocabulary. Verifiers reject rather than normalize signed input.
10. A public license is explicitly public, free, offline, permanent, and has no subject. It remains playable without network authentication.
11. Time-limited grants use `[valid_from, expires_at)` and fail closed without acceptable trusted time. Compromised devices can bypass local policy; v0.2 does not claim DRM-grade enforcement.
12. Time-anchor objects are defined and signed. Authority selection and issuance infrastructure remain deployment concerns.
13. Playback receipt generation and settlement integration are v0.3 work.

## Exact signing profiles

All profiles use Ed25519, unpadded base64url, duplicate-key-free I-JSON, and RFC 8785 JCS. Each ASCII domain is followed by one NUL byte:

| Object | Domain | Excluded top-level member |
|---|---|---|
| Manifest | `OMP-MANIFEST-v0.2` | `signature` |
| Identity document | `OMP-IDENTITY-DOCUMENT-v0.2` | `proofs` |
| Key lifecycle event | `OMP-KEY-LIFECYCLE-EVENT-v0.2` | `proofs` |
| License | `OMP-LICENSE-v0.2` | `signature` |
| Trust bundle | `OMP-TRUST-BUNDLE-v0.2` | `signatures` |
| Time anchor | `OMP-TIME-ANCHOR-v0.2` | `signature` |

Identity commitment uses SHA-256 over `OMP-IDENTITY-GENESIS-v0.2 || 0x00 || JCS(genesis_body)`. The full construction is in `docs/signing-profiles-v0.2.md`.

## Contradictions resolved

- v0.1 field extension versus compatibility: exact parallel version dispatch and newly issued v0.2 objects.
- Mandatory recovery versus single-key control: threshold one is ordinary control; higher thresholds are optional.
- Generic media domain versus type separation: exact type domains.
- Revocation invalidating history: separate authenticity and current-trust results.
- TOFU being trusted: persistent explicit unverified state.
- Arbitrary roles versus versioned vocabulary: closed v0.2 vocabulary.
- Public `*` sentinel versus explicit public license: sentinel removed; public licenses omit `subject_id`.
- Embedded revocations versus signed lifecycle events: bundles carry independently signed lifecycle objects.
- Unsigned bundle container: top-level bundle signatures are required.
- Optional time-anchor format: schema and domain are defined; infrastructure remains deferred.
- Receipt/settlement roles: removed from v0.2 operational roles and deferred to v0.3.

## Vector verification

`cryptographic-vectors.json` contains deterministic public test seeds, keys, signed objects, canonical bytes, payload bytes, hashes, and signatures for all six profiles. Python generation uses independent `rfc8785` and `cryptography` packages. Rust independently verifies with `serde_jcs`, `sha2`, and `ed25519-dalek`. Both agree on every canonical sequence, payload hash, signature, and identity commitment. v0.1 fixtures still pass unchanged.

## Stable error states

`docs/error-codes-v0.2.md` distinguishes malformed objects, invalid signatures, domain mismatch, unknown/unverified identities, unknown/unauthorized/revoked keys, conflict/staleness/rollback, asset errors, invalid/not-yet-valid/expired licenses, and unavailable or rolled-back trusted time.

## Remaining blockers

The former internal blockers were dispositioned on 2026-10-26: ADRs 007-011
were approved and ADR-012 was deferred with closed schemas. The later W0 audit
found the pre-existing historical key-validity timestamp mapping still needs
an owner decision. External assurance remains required before release.

## Readiness

The cryptographic construction and vectors are internally consistent and
independently reproduced. Controlled implementation is conditional on owner
approval of ADRs 007-012. Test-only verification code does not enable v0.2
behavior in any production crate.
