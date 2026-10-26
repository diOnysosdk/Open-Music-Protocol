# ADR 005: Explicit offline license semantics

- Status: Provisionally accepted for normative-draft verification
- Scope: OMP v0.2 only
- Supersedes: no v0.1 behavior

## Context

## Owner resolution (2026-10-26)

Public licenses are explicit: `audience = public`, `mode = free`,
`offline = true`, permanent policy, and no `subject_id`. The earlier `*`
sentinel is rejected. Such works remain playable without authentication or
network freshness. Time-limited licenses fail closed without acceptable
trusted-time evidence. The v0.2 time-anchor data structure and signing domain
are defined, while authority selection and issuance infrastructure remain
local policy and deferred operations.


OMP v0.1 has `mode`, `offline`, `valid_from`, and optional `expires_at`.
It requires `valid_from < expires_at`, but deliberately leaves normalized
clock semantics and offline expiry enforcement unresolved. A compromised
device can roll back its wall clock, so the protocol must not describe an
ordinary local clock check as DRM or strong enforcement. At the same time,
unrestricted music must remain playable without a network or an account.

## Decision

Version 0.2 licenses add two signed fields:

- `audience`: `public` or `subject`;
- `offline_policy`: an object with `kind` equal to `permanent` or
  `time_limited`.

The legacy `offline` field remains required. `offline: false` means the grant
does not authorize offline playback, regardless of `offline_policy`.

### Permanent grant

`offline_policy.kind = permanent` has no expiry. It MUST NOT contain
`expires_at`. A public, permanent, offline, free license is an unrestricted
grant and MUST remain playable without network authentication, revocation
refresh, device enrollment, or a trusted clock. Implementations MAY warn about
stale issuer trust information but MUST NOT convert such a warning into an
online requirement.

For a public grant, `subject_id` is absent. Subject grants require a
self-certifying OMP party identifier.

### Time-limited grant

`offline_policy.kind = time_limited` requires `expires_at` and the signed
value `clock_requirement = trusted_time`. There is no implicit grace period.
Playback is authorized exactly when:

```text
valid_from <= evaluation_time < expires_at
```

after RFC 3339 timestamps are normalized to UTC. The original timestamp text
remains part of the signed payload and is never rewritten before signature
verification.

`trusted_time` is supplied by the player, not claimed by the license. It is
one of:

1. an OS secure/rollback-resistant clock;
2. a previously verified signed time anchor plus trustworthy monotonic elapsed
   time;
3. no trusted time.

When trusted time is unavailable, a time-limited grant MUST fail closed with
`OMP_TRUSTED_TIME_UNAVAILABLE`. A player MAY offer a separate user override
mode, but it MUST label the result unverified and MUST NOT emit a protocol
claim that the license was valid. A plain wall clock is advisory only.

Signed time anchors are optional transport-neutral v0.2 objects defined by
`time-anchor.schema.json`. No central time service is mandated: an issuer,
user-selected trust provider, local enterprise authority, or other configured
signer can issue one. Authority selection and issuance infrastructure are
deployment concerns and remain deferred.

### License evaluation order

1. Parse with duplicate-key rejection and dispatch by exact schema version.
2. Resolve the issuer key under the offline trust rules.
3. Verify the license signature using the version-specific signing domain.
4. Confirm manifest and license `license_id` and `recording_id` match.
5. Confirm `offline` is true.
6. Apply `audience` binding. Public grants require no local identity;
   subject grants require the configured subject identity.
7. Apply validity interval and clock rules.

Failure at any step is explicit and never silently accepted.

## Backwards compatibility

V0.1 licenses continue to be parsed and authenticated exactly as v0.1. They
are not upgraded in place and never use v0.2 semantics based on field values.
An explicit migration creates and signs a new v0.2 license:

- v0.1 `free` or `purchase` without `expires_at` may migrate to `permanent`;
- any v0.1 license with `expires_at` may migrate to `time_limited`;
- v0.1 `subscription` without `expires_at` has no deterministic migration and
  requires issuer action;
- the migrator must choose `audience`; no subject is inferred as public.

The original v0.1 object remains independently verifiable.

## Security and tradeoffs

- Fail-closed time-limited access can deny playback after secure-clock loss.
- Fail-open behavior is friendlier but makes expiry meaningless on hostile
  devices; it is not the protocol-valid path.
- Revocation cannot reliably affect a permanently offline device. Permanent
  public grants intentionally prioritize durable access.
- A signed license proves an issuer made a statement, not that it owned the
  rights or received payment.
- Subject-bound licenses expose a stable identifier unless pairwise identities
  are used; privacy guidance is required.

## Remaining review question

Decide whether every subscription license MUST be time-limited. All other
questions formerly listed here were resolved by the owner decision above and
the exact profiles in `docs/signing-profiles-v0.2.md`.

