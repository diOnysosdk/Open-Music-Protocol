# ADR 010: Trusted-time evidence and clock rollback

- Status: Normative proposal — owner approval required
- Scope: v0.2 time-limited offline decisions
- Depends on: ADR-005 and `time-anchor.schema.json`

## Proposed normative decision

Acceptable trusted-time evidence is one of:

1. a platform clock explicitly documented as rollback-resistant and accepted
   by local policy; or
2. a valid OMP time anchor from a locally trusted `time-anchor` authority,
   plus a monotonic elapsed-time source that has not reset.

Network time, filesystem timestamps, unauthenticated wall clocks, manifest
timestamps, and signer-controlled license timestamps are not trusted-time
evidence by themselves. No central time authority is required.

For an anchor, the verifier records `observed_at`, local monotonic reading,
anchor sequence/hash, and durable high-water time. At evaluation it computes:

```text
lower_bound = observed_at + nonnegative_monotonic_elapsed
upper_bound = lower_bound + configured_clock_uncertainty
```

Evidence is acceptable only while monotonic state remains continuous and
elapsed time does not exceed `max_age_seconds`. A time-limited license is valid
only when the entire interval `[lower_bound, upper_bound]` lies within
`[valid_from, expires_at)`. Boundary uncertainty therefore fails closed.

Every accepted observation advances a durable high-water lower bound. If new
evidence has an upper bound earlier than that high-water value, sequence/hash
regresses, monotonic state resets without a new trusted anchor, or persisted
state is missing, return `OMP_TRUSTED_TIME_ROLLBACK` or
`OMP_TRUSTED_TIME_UNAVAILABLE` and reject time-limited playback.

An unrestricted public license never requires trusted time. A user may choose
a clearly labeled non-protocol override, but software MUST NOT report a valid
OMP license decision from that override.

## Limitations

Software cannot guarantee time enforcement on a fully compromised device.
Secure clocks and monotonic storage reduce rollback risk but are deployment
capabilities, not DRM guarantees. Issuance, transport, and commercial choice
of time authorities remain outside core v0.2.

## Required tests

- Valid anchor, exact lower boundary, uncertainty crossing either boundary,
  max-age expiry, sequence rollback, wall-clock rollback, monotonic reset,
  lost persisted state, and untrusted authority.
- Equivalent timestamp offsets normalize to the same instant without changing
  signed bytes.

## Owner approval required

Approve interval-safe evaluation and zero implicit tolerance. Safest default:
`configured_clock_uncertainty = 0` only for a platform that explicitly
guarantees it; otherwise a deployment MUST configure a conservative positive
uncertainty or reject time-limited playback.

