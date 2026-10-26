# OMP v0.2 W4 implementation report

> Integration-status note: this report records the isolated W4 milestone before
> production W2/W3 APIs existed. Its W2/W3 dependency assessment is superseded
> by `docs/w2-w3-implementation-report-v0.2.md`; the isolated-state-machine and
> platform-assurance findings remain applicable.

Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1` plus approved ADR-013 amendment  
Recommendation: **CONDITIONAL GO for isolated W4 state-machine integration;
NO-GO for complete W4 integration or production release**.

## Implemented

The new `omp-identity` crate contains only W4-owned behavior:

- validation of W2/W3-authenticated identity and lifecycle fact chains;
- distinct-threshold authorization, including the 2-of-3 profile;
- deterministic identity and lifecycle fork detection;
- rollback/high-water validation;
- deterministic merge of authenticated portable-bundle facts;
- explicit `VERIFIED`, `UNVERIFIED_TOFU`, and `UNKNOWN` bootstrap state;
- separate authenticity, authorization, current trust, freshness, and playback
  result types;
- ADR-013 current/historical/unknown authorization evaluation;
- strict `PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` gating;
- ADR-007 and ADR-008 precedence inputs;
- durable-pin records, local hash chaining, atomic compare-and-swap storage
  trait, crash simulation, and monotonic progression checks.

The crate performs no network access and contains no registry, blockchain,
payment, settlement, telemetry, player, or W5/W6/W7 implementation.

## Deliberately blocked W2/W3 integration

`ValidatedFactProvider` is the explicit adapter boundary. W2/W3 must provide:

1. strict v0.2 wire models and duplicate-safe schema-equivalent parsing;
2. self-certifying identity commitment calculation and key creation APIs;
3. the six typed signing profiles and exact exclusion behavior;
4. Ed25519 proof/signature verification and complete-object hashes;
5. signed trust-bundle verification before conversion to
   `ValidatedTrustBundle`;
6. conversion tests proving that no unauthenticated field enters W4 facts.

`omp-identity` does not contain domain constants, RFC 8785 canonicalization,
Ed25519 operations, wire identity models, or alternative signing behavior.
Consequently, self-certifying identity issuance and signed portable-bundle
authentication remain unavailable until W2/W3 land.

## Public API summary

- `ValidatedFactProvider`: required W2/W3 adapter contract.
- `ValidatedIdentityDocument`, `ValidatedLifecycleEvent`,
  `ValidatedTrustBundle`: authenticated fact inputs, not wire models.
- `validate_identity_chain`, `validate_lifecycle_chain`: ordering, linkage,
  threshold, and transition validation.
- `detect_identity_forks`, `detect_lifecycle_forks`: deterministic conflicts.
- `merge_trust_facts`, `current_key_status`: offline trust-state processing.
- `evaluate_authorization`, `evaluate_playback`: ADR-013/007/008 policy axes.
- `DurablePin`, `TrustState`, `TrustStateStore`, `update_trust_state`,
  `verify_state_progression`: persistence boundary and anti-rollback logic.

## Security assumptions and platform limits

- Facts are safe only when produced by a conforming W2/W3 adapter. Directly
  constructing them from untrusted input is prohibited.
- `MemoryTrustStore` is test/ephemeral only and offers no reboot rollback
  resistance.
- A production `TrustStateStore` must provide authenticated storage, durable
  atomic compare-and-swap, monotonic high-water metadata, crash consistency,
  and fail-closed behavior after integrity-key loss or restore rollback.
- The local state hash chain detects inconsistent progression when anchored by
  trusted state; by itself it is not secure hardware or an authenticated MAC.
- Signer-controlled timestamps are absent from W4 authorization inputs and
  cannot create historical authorization.
- Cryptographic validity remains distinct from legal ownership.

## Acceptance matrix

| W4 criterion | Status | Evidence/blocker |
|---|---|---|
| Self-certifying identity creation | Blocked | Requires W2 model and W3 commitment/key APIs |
| Identity chain and threshold state machine | Pass in isolation | Unit tests cover threshold and linkage |
| Single-key and optional 2-of-3 recovery | Partial | Threshold engine passes; cryptographic proof adapter awaits W3 |
| Rotation/revocation and historical authorization | Pass in isolation | Lifecycle and ADR-013 tests |
| Deterministic fork detection | Pass | Arrival-order-independent tests |
| Rollback and monotonic state | Pass in isolation | High-water/hash-chain tests |
| Signed portable trust-bundle verification | Blocked | Signature/schema verification belongs to W2/W3 |
| Deterministic validated-bundle merge | Pass | Merge-order test |
| TOFU without promotion | Pass | Persistence test |
| Separate result axes | Pass | Public enums/result model |
| Durable pins and atomic updates | Pass at interface/state-machine level | Production platform backend still required |
| ADR-013 exception containment | Pass | Restricted, TOFU, altered, revoked, conflict cases |
| v0.1 compatibility | Pass | Existing workspace and Python regression suites |

## Remaining blockers

- Validated W2 wire models and W3 crypto/profile APIs.
- Cross-crate conversion tests against every frozen cryptographic vector.
- Production platform `TrustStateStore` implementations and independent
  crash/rollback/secure-storage review.
- External identity state-machine and privacy review before release.

No normative contradiction was introduced or discovered in the isolated state
machines. Complete W4 integration must remain blocked until the W2/W3 adapter
requirements above are satisfied.
