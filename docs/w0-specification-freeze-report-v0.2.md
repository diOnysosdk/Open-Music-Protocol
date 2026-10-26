# OMP v0.2 W0 specification freeze report

Date: 2026-10-26  
Revision: `OMP-v0.2-w0-freeze.1`  
Artifact manifest SHA-256: `fc912bbcfab93b72f958347a3fabc0fef6e781977b2b705c4958687d72e12218`

## Result

The approved v0.2 wire schemas, signing profiles, ADR dispositions, fixtures,
and interoperability vectors are frozen at the revision above. All 42 artifact
hashes are recorded in `omp-spec-v0.2-draft/SHA256SUMS` and were independently
recomputed after the final edits.

Recommendation: **GO for controlled W1/W2/W3 implementation, NO-GO for W4 and
for production release**. W4 remains blocked on the one owner decision under
"Remaining decision" below. No W2-W7 production behavior was implemented.

## Integrated decisions

- ADR-007 accepted: the exact, previously authenticated pinned-public exception
  returns `VALID_CONFLICTED_PINNED`; it never resolves the fork.
- ADR-008 accepted: previously verified and pinned permanent subject grants may
  return `VALID_STALE`; stale is never silently upgraded to fresh.
- ADR-009 accepted: subscriptions are subject-bound and explicitly time-limited
  with exclusive expiry.
- ADR-010 accepted: trusted-time evidence uses conservative intervals and
  durable rollback protection; required time evidence fails closed.
- ADR-011 accepted: v0.2 has one canonical NFC metadata presentation.
- ADR-012 deferred: v0.2 has no extension envelope; all undeclared fields fail
  closed as `OMP_SCHEMA_INVALID`.

The audit also removed stale generic-domain language. The six type-specific
v0.2 signing domains and their top-level exclusions remain unchanged. v0.1
continues to use exactly `OMP-SIGNED-OBJECT-v0.1 || 0x00` with no reinterpretation.

## Validation evidence

Executed from the repository root:

```powershell
& $python omp-spec-v0.2-draft/tools/generate_audio_fixtures.py
& $python -m pytest -p no:cacheprovider omp-spec-v0.2-draft/tests omp-spec-v0.1/tests -q
# 19 passed, 1 skipped, 0 failed

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# 12 passed, 0 failed
cargo doc --workspace --no-deps
# succeeded
```

The one skip is runtime symlink creation on Windows without the required
privilege; the corresponding normative negative vector is present. Frozen
artifact verification reported `42/42 frozen artifact hashes verified`.
Regeneration did not change the WAV, FLAC, or fixture index. No file under
`crates/` changed.

## Remaining decision

Protocol-owner approval is still required for the exact timestamp used to
evaluate historical signing-key validity for each signed object type. ADR-001
requires evaluation at an object's normative protocol timestamp, but the
accepted material does not map every object type to a field or define how a
signer-controlled timestamp is constrained. Inferring this would introduce
new security-sensitive behavior.

This does not alter schemas, canonical signing bytes, vectors, or W1/W2/W3.
W4 identity/trust implementation MUST remain blocked until the mapping is
approved and added as a normative semantic invariant with boundary vectors.

## Remaining release blockers

- Independent cryptographic/JCS and identity-state-machine review.
- Independent schema and semantic-validator parity review.
- Linux symlink plus Windows junction/reparse/TOCTOU execution.
- Unicode/path-confusability, privacy, legal, dependency-license, SBOM,
  secret-scanning, and reproducible-build review.
- Resolution and tests for the historical key-validity timestamp mapping.
- Final protocol-owner and independent assurance sign-off on the release
  candidate.

W1 may own immutable conformance packaging, W2 exact version dispatch/models,
and W3 typed cryptographic profiles in parallel. None may change a frozen
artifact without a new revision and protocol review.
