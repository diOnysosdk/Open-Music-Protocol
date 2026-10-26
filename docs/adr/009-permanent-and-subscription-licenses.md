# ADR 009: Permanent grants and subscription expiry

- Status: Accepted — protocol owner approved 2026-10-26
- Scope: v0.2 offline license policy
- Depends on: ADR-005, ADR-008

## Proposed normative decision

The following combinations are valid:

- `audience=public`, `mode=free`, `offline=true`: MUST use `permanent`, MUST
  omit `subject_id` and `expires_at`, and remains unrestricted offline.
- Subject `free` or `purchase`: MAY use `permanent` or `time_limited`.
- Subject `subscription`: MUST use `time_limited`, MUST include `expires_at`,
  and MUST require trusted time.
- `offline=false`: grants no offline playback regardless of policy fields.

A permanent grant never expires. Its signature and original authorization are
historical facts. A known revocation or conflict can change current trust but
does not erase the signed license. Public unrestricted playback follows the
availability rule in ADR-005/ADR-008. Permanent subject playback follows the
stale-trust rule in ADR-008.

Time-limited authorization is exactly
`valid_from <= evaluation_time < expires_at`. There is no implicit grace
period. Failure codes distinguish `OMP_LICENSE_NOT_YET_VALID`,
`OMP_LICENSE_EXPIRED`, and `OMP_TRUSTED_TIME_UNAVAILABLE`.

A v0.1 subscription without expiry has no automatic migration. Issuer action
is required; migration MUST NOT invent an expiry or permanent entitlement.

## Security consequences

- Mandatory subscription expiry prevents an ambiguous perpetual subscription.
- A compromised client can bypass local enforcement; OMP does not claim DRM.
- Public permanent grants intentionally cannot be disabled by network absence.
- Legal rights and payment state are outside signature authenticity.

## Required tests

- Reject permanent subscription, public time-limited, public purchase, public
  subject ID, and subscription without expiry.
- Exercise both interval boundaries and no trusted time.
- Verify permanent public playback with no network, clock, or fresh bundle.

## Protocol-owner disposition

Approved 2026-10-26. Every v0.2 subscription is explicitly time-limited;
nonconforming subscription objects are rejected.

