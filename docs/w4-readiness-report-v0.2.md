# OMP v0.2 W4 readiness report

Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1`  
Amendment fixture profile: `OMP-v0.2-historical-authorization-amendment-1`  
Recommendation: **GO for controlled W4 production implementation; NO-GO for production release**.

## Disposition

ADR-013 is provisionally accepted with all owner conditions incorporated.
`AUTHORIZATION_UNKNOWN` is a distinct authorization-axis value.
`PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` is a playback-decision value, not an
authorization success or `OMP_*` error.

The availability exception requires exact previously verified and locally
pinned unrestricted public content, an eligible rollback-resistant durable pin,
and no known revocation, compromise, conflict, alteration, or rollback. TOFU
without demonstrated authorization is ineligible. Restricted and authority-
granting operations fail closed.

ADR-007 remains the exclusive conflict path; its
`VALID_CONFLICTED_PINNED` requirements are not widened. ADR-008 remains the
exclusive stale permanent-subject path.

## Evidence and fixtures

The durable pin requirements, authorization matrix, playback matrix, namespace
analysis, circular-trust prevention, and threat analysis are normative in
`docs/historical-key-authorization-v0.2.md`.

Thirteen executable semantic cases cover current and historical authorization,
compromised-key backdating, boundary-crossing observations, unknown
authorization, eligible pins, TOFU, rollback, altered content, restricted
licenses, publishing, missing trusted time, conflict denial, and ADR-007's
separate proven-history path.

## Validation

- Frozen baseline: 42/42 hashes unchanged.
- Python amendment, v0.2, and v0.1 suites: 21 passed, 1 Windows symlink skip.
- Rust workspace: 12 passed, 0 failed.
- Formatting, Clippy with warnings denied, and documentation: passed.
- Schema, signing-domain, canonical-byte, cryptographic-vector, and v0.1
  behavior changes: none.
- W4 production code changes: none.

## Release blockers

Independent review remains required for the state machine, durable local-store
anti-rollback design, platform secure-storage assumptions, crash consistency,
backup/restore behavior, privacy, and all previously recorded release gates.
These are release blockers, not protocol-owner decisions blocking controlled
W4 implementation.

## Outstanding protocol-owner approvals

None for controlled W4 implementation. Final production release still requires
the independent assurance and release sign-offs defined by the v0.2 review
checklist.
