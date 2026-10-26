# ADR 008: Trust freshness and offline verification status

- Status: Accepted — protocol owner approved 2026-10-26
- Scope: v0.2 offline trust evaluation
- Depends on: ADR-002, ADR-007

## Context

Signature authenticity does not establish current authorization, and an
offline verifier cannot know about events it has not received. A Boolean
result would either hide uncertainty or turn connectivity into DRM.

## Proposed normative decision

Verification returns four independent axes:

1. `authenticity`: `VALID` or `INVALID`;
2. `identity_trust`: `VERIFIED`, `UNVERIFIED_TOFU`, or `UNKNOWN`;
3. `current_status`: `ACTIVE`, `REVOKED`, `CONFLICT`, or `UNKNOWN`;
4. `freshness`: `FRESH`, `STALE`, or `UNKNOWN`.

Implementations MUST preserve these axes and may additionally return the
stable error code from `docs/error-codes-v0.2.md`. They MUST NOT map
`UNVERIFIED_TOFU`, `STALE`, or `UNKNOWN` to `VERIFIED`/`FRESH`.

A signed trust bundle is `FRESH` only when acceptable trusted-time evidence
shows `evaluation_time <= next_update_at`. It is `STALE` when trusted time is
later than `next_update_at`. It is `UNKNOWN` when `next_update_at` or acceptable
trusted time is absent. Local policy MAY impose an earlier deadline but MUST
NOT extend the signed deadline.

Freshness applies to knowledge, not signature mathematics. A stale bundle can
still authenticate historical signatures and expose known revocations.

### Offline decision matrix

- Bad signature/schema/role: reject as `INVALID`.
- Known revocation covering signing time: authenticity MAY remain `VALID`, but
  current trust is `REVOKED` and restricted operations fail.
- Conflict: apply ADR-007.
- Unknown identity or key: fail closed for protocol-valid playback; an
  explicit TOFU action may create `UNVERIFIED_TOFU` for later evaluation.
- Unrestricted public content: `STALE` or `UNKNOWN` freshness alone MUST NOT
  prevent playback; expose the condition.
- Permanent subject license previously verified and pinned: stale freshness
  MAY permit playback if no known revocation/conflict exists, with
  `VALID_STALE`; unknown identity/key still fails.
- Time-limited or subscription license: require `FRESH` trust and acceptable
  trusted time; otherwise fail closed with `OMP_TRUST_STALE` or the applicable
  time error.

No protocol default imposes a wall-clock maximum in addition to the signed
`next_update_at`. Publishers therefore cannot force network use for public
content, while restricted profiles can require timely bundles.

## Rollback

The trust store records highest observed sequences and hashes. A lower
sequence, missing previously known event, or older conflicting snapshot yields
`OMP_TRUST_ROLLBACK`, not merely `STALE`. If durable monotonic state is lost,
freshness becomes `UNKNOWN`; time-limited decisions fail closed.

## Required tests

- Exact `next_update_at` is fresh; one representable instant later is stale.
- Missing next-update or trusted time is unknown.
- Bundle arrival order cannot erase a revocation or conflict.
- Public unrestricted playback succeeds under stale/unknown freshness while
  time-limited playback fails.
- TOFU remains unverified across repeated imports.

## Protocol-owner disposition

Approved 2026-10-26. Only previously verified and pinned permanent subject
grants may use explicit `VALID_STALE`; deployments may be stricter. There is
no global freshness duration beyond signed `next_update_at`.

