# OMP v0.2 implementation readiness report

Date: 2026-10-26  
Historical status: superseded by the W0 specification-freeze report.

No v0.2 production Rust code was changed during this milestone. Controlled
implementation may start only after the protocol owner approves or rejects
ADRs 007-012 and the resulting normative text, schemas, and fixtures are
frozen at one revision.

## Audit and resolved proposals

The v0.1 implementation, authoritative v0.1 bundle, all v0.2 architecture and
security documents, ADRs, schemas, signing profiles, and vectors were reviewed.
The following conservative proposals now have dedicated ADRs:

- ADR-007: deterministic fork detection; no arrival-order winner; a narrow
  `VALID_CONFLICTED_PINNED` exception only for exact, previously authenticated,
  unrestricted artifacts.
- ADR-008: separate authenticity, identity trust, current status, and freshness;
  stale/unknown trust alone cannot disable unrestricted public playback.
- ADR-009: public grants are permanent; subscriptions are subject-bound and
  time-limited; `[valid_from, expires_at)` has no implicit grace period.
- ADR-010: time decisions use a conservative evidence interval; rollback,
  restart without durable state, and an interval crossing a license boundary
  fail closed for time-limited grants.
- ADR-011: v0.2 signs one canonical NFC presentation plus optional BCP 47
  language tags; alternate translations/transliterations are deferred.
- ADR-012: proposed URI-keyed extension envelope with explicit criticality.
  Until approved, schemas remain closed and all unknown extension members fail
  as `OMP_SCHEMA_INVALID`.

The license schema and negative vectors enforce the proposed subscription rule.
No existing v0.1 object or signing payload is reinterpreted. Cryptographic
authenticity, present trust, playback entitlement, and legal ownership remain
separate concepts.

## Interoperability evidence

The repository contains a CC0, integer-defined 250 ms mono PCM fixture in WAV
and FLAC, a pinned generator, a machine-readable index, multi-asset manifest,
security-case catalog, and executable tests. Regeneration produced no media or
index diff.

Published SHA-256 values:

- `omp-triangle-250ms.wav`: `7968796923996897acaa2a734d5f9aa44023c521a5d8eaeda24a04f3e2745a06`
- `omp-triangle-250ms.flac`: `b7a34c178dc61f86b9e7e542e6c000f1d6f56b8c5b364caef27319b86781d53d`
- `fixture-index.json`: `431aa3f75f1beaf2eadd3b47225fa4170ff42a7fe3119c5ccfc1e104a8daea04`
- `cryptographic-vectors.json`: `5031630c0712c841be7d3f7253a294febfec91a7628f70a7f43e0f0027556543`

Coverage includes hash/size alteration, deterministic multi-asset selection,
portable-path rejection, runtime symlink escape, signature tampering/truncation,
wrong key/domain, unknown/revoked keys, identity forks, license expiry and
missing trusted time, non-NFC metadata, and closed-schema extension handling.
The RFC 8785 fixture contains the complete Appendix B number table, non-finite
rejections, and the Section 3.2.3 UTF-16 ordering example.

## Validation commands and results

```powershell
$python = Join-Path $env:TEMP 'omp-spec-python-venv\Scripts\python.exe'
$env:PYTHONDONTWRITEBYTECODE = '1'
& $python omp-spec-v0.2-draft/tools/generate_audio_fixtures.py
& $python -m pytest -p no:cacheprovider omp-spec-v0.2-draft/tests omp-spec-v0.1/tests -q
# 19 passed, 1 skipped (Windows symlink privilege), 0 failed

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# 12 passed, 0 failed
cargo doc --workspace --no-deps
# succeeded
```

The skipped runtime symlink test has a normative negative vector. Linux CI and
Windows reparse-point CI remain mandatory before release. Rust independently
verified every Python-generated v0.2 JCS/signature vector, while all v0.1
contract and regression tests continued to pass.

## Owner dispositions after this report

ADRs 007-011 were approved on 2026-10-26. ADR-012 was deferred and schemas
remain closed. See `docs/decision-register-v0.2.md` and the later W0 report.

## Remaining release blockers

- Independent cryptographic/JCS and identity-state-machine review.
- Independent Unicode and Windows/Linux filesystem containment review.
- Linux symlink and Windows junction/reparse/TOCTOU test execution.
- Privacy, legal, dependency-license, SBOM, secret-scan, and reproducible-build
  review described in `docs/external-review-checklist-v0.2.md`.
- Protocol-owner sign-off on the frozen schema/vector revision.

The dependency-ordered workstreams, acceptance criteria, and test ownership are
defined in `docs/implementation-plan-v0.2.md`. Subject to the six owner decisions,
the repository is ready to freeze and begin controlled implementation; it is
not ready to claim production or release approval.
