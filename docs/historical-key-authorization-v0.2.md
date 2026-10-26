# OMP v0.2 historical key authorization amendment proposal

Baseline: `OMP-v0.2-w0-freeze.1`  
Status: provisionally accepted semantic amendment, 2026-10-26  
Wire impact: none

## Purpose

Signature validity proves that a particular Ed25519 key signed exact bytes. It
does not by itself prove that the key held the required OMP role at a claimed
past time. This amendment defines deterministic authorization without trusting
a signer's own timestamp as evidence of when a signature was created.

The verifier MUST return cryptographic authenticity independently from key
authorization, current trust, entitlement, and legal ownership.

## Existing signed fields and authorization matrix

Every timestamp below is inside the object's existing frozen signing payload.
Being signed authenticates the assertion; it does not independently establish
that the asserted time was true.

| Object | Existing time/order fields | Required signing authority | Authorization reference | Backdating treatment | Historical/current result |
|---|---|---|---|---|---|
| Manifest | `created_at` | operational key with `manifest` role | Current accepted identity state, or a prior authenticated observation record | `created_at` is never proof of signing time | Current authorization may be established now; historical authorization requires prior evidence |
| Identity document | `genesis_body.created_at`, `issued_at`, `sequence`, `previous_document_hash` | genesis recovery threshold for sequence 0; predecessor-authorized recovery threshold thereafter | `sequence` plus complete predecessor hash | timestamps cannot reorder or authorize a document | Authorization is established by chain order; current status separately reflects later fork/revocation |
| Key lifecycle event | `sequence`, `previous_event_hash`, `effective_at`, `issued_at`, optional `compromise_from` | recovery threshold authorized by the applicable accepted identity branch | lifecycle sequence plus complete predecessor hash | `issued_at`, `effective_at`, and `compromise_from` take effect only after proof/chain validation; they cannot authorize the event | Event authorization is order-based; its validated effect may change current trust and historical results |
| License | `valid_from`, optional `expires_at` | operational key with `license` role | Current accepted identity state, or a prior authenticated observation record | license interval controls entitlement only; it is not signature-creation evidence | Key authorization and license-time validity are evaluated independently |
| Trust bundle | `created_at`, optional `next_update_at`; nested objects have their own fields | operational key with `trust-bundle` role for bundle provenance | Current accepted publisher identity state, or prior authenticated observation; nested objects validate independently | bundle timestamps prove neither publisher key history nor nested-object timing | A bad/unknown bundle signature invalidates provenance, not an otherwise independently valid nested signature |
| Time anchor | `observed_at`, `issued_at`, `sequence`, optional `previous_anchor_hash`, `max_age_seconds` | operational key with `time-anchor` role from a locally trusted authority | Current accepted authority state or a previously pinned authority-key epoch; anchor sequence/hash prevents rollback | an anchor MUST NOT use its own time to establish its signer's historical authorization | Only after signer authorization is established may the anchor provide time evidence for other decisions |

## Authorization evidence model

For a signed object and required role, the verifier returns one authorization
state:

- `AUTHORIZED_CURRENT`: the key is present with the required role on the
  accepted, nonconflicted identity branch and no currently known lifecycle
  fact revokes or supersedes it. This is a statement at evaluation, not at the
  object's claimed timestamp.
- `AUTHORIZED_HISTORICAL`: durable evidence proves the exact object hash was
  observed while the key was authorized for the role.
- `AUTHORIZATION_UNKNOWN`: the signature is valid but neither current nor
  historical authorization is established.
- `UNAUTHORIZED`: authenticated evidence proves wrong role, outside a proven
  key-validity interval, or invalid predecessor/threshold authorization.
- `REVOKED` or `CONFLICT`: current authenticated lifecycle evidence produces
  the corresponding existing trust state.

An authenticated observation record is local trust-store evidence, not a new
wire object. It contains the complete object SHA-256, signer identity and key,
required role, accepted identity-document hash and sequence, highest lifecycle
event hash and sequence, observation provenance, and—when a time claim is
needed—a trusted-time interval plus rollback-resistant persistence metadata.
The record is useful only if its identity/lifecycle snapshot still validates
and its stored state has not rolled back.

An object timestamp alone, filesystem time, import time, bundle arrival time,
or unauthenticated wall clock MUST NOT produce `AUTHORIZED_HISTORICAL`.

### Durable pin evidence

A pin eligible for the availability exception MUST contain:

- exact SHA-256 hashes of the manifest and public license plus every selected
  asset hash and size;
- signer identity, key ID, required role, genesis hash, accepted identity
  branch-tip hash/sequence, and lifecycle tip hash/sequence;
- the prior authorization result (`AUTHORIZED_CURRENT` or
  `AUTHORIZED_HISTORICAL`) and verification profile version;
- pin origin `explicit` or `verified-introduction`; `tofu-unverified` is never
  eligible;
- an atomic monotonic record generation, previous-record hash, and trust-store
  high-water marks; and
- locally authenticated integrity bound to the installation trust store.

The pin MUST be written only after full signature, role, asset, public-license,
and then-known trust validation succeeds. Importing or repeatedly observing a
TOFU object cannot create eligible evidence. Missing fields, a hash mismatch,
non-atomic state, a lower generation/high-water mark, a broken record chain,
lost integrity key, or restored older state makes the pin ineligible and
returns the applicable rollback/unknown result.

A durable pin records that authorization was previously demonstrated. Without
independent trusted-time evidence it does not prove a wall-clock historical
boundary and therefore does not itself produce `AUTHORIZED_HISTORICAL`.

## Conservative evaluation policy

1. Validate duplicate-safe I-JSON, the exact frozen schema, domain, canonical
   bytes, and Ed25519 signature before authorization evaluation.
2. Resolve the signer only through the accepted self-certifying identity branch
   or an explicit legacy binding. Unknown keys return `OMP_KEY_UNKNOWN`.
3. Validate identity documents and lifecycle events by threshold proofs and
   sequence/hash order. Their timestamps never establish their own authority.
4. Apply every known fork, rollback, role, rotation, and revocation fact.
5. Prefer `AUTHORIZED_CURRENT` when current authorization is sufficient.
6. If current authorization is absent, accept `AUTHORIZED_HISTORICAL` only from
   a valid observation record whose evidence interval lies wholly inside the
   key's validity interval and wholly before the applicable revocation boundary.
7. For `compromised`, the boundary is `compromise_from` when present, otherwise
   `effective_at`. An observation interval touching or crossing the boundary
   does not prove historical authorization.
8. `superseded`, `lost`, and `retired` use `effective_at`. Rotation never makes
   a predecessor signature mathematically invalid.
9. Missing acceptable trusted time yields `AUTHORIZATION_UNKNOWN`, not
   `AUTHORIZED_HISTORICAL`, when the decision depends on a wall-clock boundary.
10. An unresolved fork returns `CONFLICT`; ADR-007 remains the only exception.

No signature is retried under another domain, and no timestamp is rewritten.

## Offline unrestricted playback

An unrestricted public manifest/license whose key is `AUTHORIZED_CURRENT` may
play without trusted time or network access. Exact artifacts with a durable
prior `AUTHORIZED_HISTORICAL` observation may continue under ADR-007/ADR-008.

If an exact pinned public artifact has a valid signature and matching asset but
historical authorization is now `AUTHORIZATION_UNKNOWN`, playback MAY return
`PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` only when the durable-pin requirements
above pass and current status is neither `REVOKED` nor `CONFLICT`. The result
MUST retain authorization `AUTHORIZATION_UNKNOWN`; it is a playback decision,
not an authorization success.

The exception MUST NOT authorize subject licenses, publishing, license
issuance, delegation, rights changes, paid entitlements, trust-bundle or
time-anchor authority, or identity/key lifecycle operations. Altered content,
known compromise/revocation, conflict, and rollback are never bypassed.
Conflict handling remains exclusively ADR-007; its stricter evidence rules and
`VALID_CONFLICTED_PINNED` status take precedence. ADR-008 remains unchanged.

For ADR-007, the phrase "authorized on the pinned branch at their signed
protocol times" is satisfied only by `AUTHORIZED_HISTORICAL` under this
amendment; the object's claimed timestamp alone never satisfies it. Thus the
new unknown-authorization exception cannot widen conflict playback.

Subject-bound, time-limited, trust-publishing, identity-management, and
time-authority decisions fail closed on `AUTHORIZATION_UNKNOWN`.

## Final authorization and playback matrices

| Evidence/result | Authorization axis | Restricted operations | Unrestricted playback |
|---|---|---|---|
| Active role-correct key on accepted branch | `AUTHORIZED_CURRENT` | Continue with entitlement/trust checks | Allowed after ordinary checks |
| Independent durable observation proves the boundary | `AUTHORIZED_HISTORICAL` | Continue with entitlement/trust checks | Allowed after ordinary checks |
| Valid signature but authorization not currently or historically proven | `AUTHORIZATION_UNKNOWN` | Denied | Only eligible for `PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` |
| Wrong role or proven outside authorized interval | `UNAUTHORIZED` | Denied | Denied |
| Known compromise/revocation | authorization retained separately; current status `REVOKED` | Denied | New exception denied |
| Unresolved fork | authorization retained separately; current status `CONFLICT` | Denied | ADR-007 only |
| Invalid signature or changed bytes | not evaluated | Denied | Denied |

| Playback status | Required conditions | Forbidden conditions |
|---|---|---|
| `PLAYBACK_ALLOWED` | ordinary unrestricted checks and current/historical authorization pass | any validation, binding, or entitlement failure |
| `PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` | exact unrestricted public artifact; eligible durable pin; prior demonstrated authorization; current authorization unknown | TOFU-only pin, changed bytes, rollback, revoked/compromised/conflicted state, or restricted operation |
| `VALID_CONFLICTED_PINNED` | all ADR-007 requirements | any relaxation introduced by ADR-013 |
| `VALID_STALE` | all ADR-008 requirements | unknown key, revocation, conflict, or unverified permanent grant |
| `PLAYBACK_DENIED` | any applicable fail-closed condition | none |

`PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` occupies the playback-decision namespace,
not the `OMP_*` error namespace and not the authorization axis. This avoids
colliding with existing stable error codes or implying cryptographic validity.

## Avoiding circular trust

- A time anchor's timestamps cannot authorize its own signing key.
- A trust bundle's `created_at` cannot authorize its publisher key, and the
  bundle signature cannot make invalid nested objects valid.
- A license's validity interval cannot establish when its signature existed.
- An identity/lifecycle successor is authorized only by already accepted
  predecessor proofs, never by the successor's `issued_at`.

These rules permit an already trusted time anchor to timestamp later
observations without recursively depending on the object being evaluated.

## Deterministic interoperability cases

Positive cases:

1. Active role-correct key yields `AUTHORIZED_CURRENT` despite no trusted time.
2. Pre-rotation object with a durable observation interval wholly before
   `effective_at` yields `AUTHORIZED_HISTORICAL`.
3. Compromised-key object observed wholly before `compromise_from` retains
   historical authenticity and authorization while current trust is revoked.
4. Identity update and lifecycle event validate by predecessor hash/sequence
   even when `issued_at` is not used as authorization evidence.
5. An independently authorized time anchor supplies evidence for a later
   manifest observation.
6. Unrestricted public content remains playable with current authorization and
   no network or trusted clock.

Negative cases:

1. A compromised key signs after compromise but backdates `created_at` or
   `valid_from`; no pre-boundary observation exists: `AUTHORIZATION_UNKNOWN` or
   `REVOKED`, never `AUTHORIZED_HISTORICAL`.
2. An observation interval crosses `compromise_from`: historical authorization
   is not proven.
3. Missing trusted time for a boundary-dependent historical claim returns
   `AUTHORIZATION_UNKNOWN`; a time-limited entitlement also returns
   `OMP_TRUSTED_TIME_UNAVAILABLE` where applicable.
4. A time anchor attempts to authorize its own key using `issued_at`: reject the
   authorization dependency.
5. A bundle publisher is unknown while a nested manifest independently
   verifies: provenance fails without changing the nested authenticity result.
6. Wrong role is `UNAUTHORIZED`; unknown key is `OMP_KEY_UNKNOWN`; known
   revocation is `OMP_KEY_REVOKED`; fork is `OMP_TRUST_CONFLICT`.
7. Observation-store rollback is `OMP_TRUST_ROLLBACK` or
   `OMP_TRUSTED_TIME_ROLLBACK`, never historical authorization.
8. Post-fork/new unrestricted content cannot use ADR-007's pinned exception.

Fixtures should include exact canonical objects, trust snapshots, observation
records, evaluation inputs, and all independent output axes. Arrival-order
permutations must produce identical results.

## Schema, signing, and vector impact

- Frozen schemas: no change required.
- Signing domains, exclusions, JCS bytes, signatures, and the 42 frozen
  artifacts: no change required.
- Existing cryptographic vectors: no change required.
- Added separately versioned semantic fixture profile
  `OMP-v0.2-historical-authorization-amendment-1`.
- `AUTHORIZATION_UNKNOWN` is an authorization-axis value and
  `PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` is a playback-decision value; neither
  changes the frozen `OMP_*` error namespace.

## Threat analysis

The policy prevents compromised keys from manufacturing history through
backdated signed timestamps and prevents time-anchor/trust-bundle circularity.
It preserves authentic historical signatures after rotation or revocation
without treating them as currently trusted. Durable observation records add
rollback, backup, cloning, and privacy risks; implementations need atomic
storage, high-water marks, provenance, and data-minimization controls.

No offline design can discover withheld revocations or prove an event was not
created before first observation. A fully compromised device can falsify local
policy enforcement. These limitations must not be described as DRM or legal
ownership assurance.

## Recommendation

**GO for controlled W4 production implementation** against this semantic
amendment. Production release remains NO-GO pending independent assurance.
