# ADR-002: Offline key distribution, rotation, and revocation

- Status: Accepted for `OMP-v0.2-w0-freeze.1`
- Scope: OMP v0.2 verification without mandatory network access
- Depends on: ADR-001
- Compatibility: v0.1 pinned-key verification remains valid and unchanged

## Context

## Owner resolution (2026-10-26)

Portable signed trust bundles and explicit TOFU are selected. A TOFU pin has
status `UNVERIFIED` until an explicit local action or accepted introduction
changes it; observation alone never upgrades trust. Lifecycle events use the
separate key-event schema and signing domain. Revocation preserves the event
and every historical signed object: verification reports historical
cryptographic validity independently from current `REVOKED` trust status.


Ed25519 proves possession of a private key; it does not prove that the key was
authorized for an issuer, role, or time. OMP v0.1 explicitly leaves key
distribution and revocation to deployments. OMP v0.2 needs a portable trust
model that works offline, supports rotation, and admits the unavoidable fact
that an offline device cannot know about a revocation published after its last
sync.

Trust freshness and playback entitlement are separate questions. Conflating
them would allow an unavailable network or expired trust snapshot to disable
unrestricted music, contrary to the protocol requirements.

## Decision

### Portable trust bundle

An offline verifier consumes a local trust bundle assembled from any source:
direct file transfer, QR/bootstrap exchange, removable media, application
sync, multiple mirrors, or a user-selected service. No source is mandatory.
The bundle is data, not an online API, and contains:

- a bundle format/version and unique bundle ID;
- `created_at` and optional advisory `next_update_at`;
- complete self-certifying identity-document chains used by its objects;
- signed key-status events and any conflict evidence;
- optional pinned legacy v0.1 key bindings;
- provenance statements and signatures from one or more user-selected bundle
  publishers.

Publisher signatures prove bundle provenance only. They do not override
identity proofs, resurrect revoked keys, or establish legal ownership. An
unsigned container is not a conforming trust bundle, although independently
signed artifacts extracted from it can still be verified on their own.

Trust bundles MUST be deterministic I-JSON, reject duplicate keys, and use a
dedicated signature domain. Bundle merging is set union by cryptographic hash,
followed by identity-chain validation. Conflicting events are retained as
evidence and produce `CONFLICT`, never last-writer-wins.

### Verification result, not a Boolean

Core verification returns a structured result with at least these states:

- `INVALID`: malformed object, bad signature, wrong algorithm, role mismatch,
  invalid chain, or key invalid at the object's protocol timestamp.
- `REVOKED`: an authenticated event covers the key and object timestamp under
  the approved revocation semantics.
- `CONFLICT`: valid but incompatible identity/key histories are known.
- `VALID_FRESH`: cryptographically valid and local policy considers trust data
  fresh.
- `VALID_STALE`: cryptographically valid against the newest locally available
  history, but freshness policy is exceeded or unknown.
- `UNKNOWN_IDENTITY` / `UNKNOWN_KEY`: required local trust material is absent.

No state that contains `INVALID`, `REVOKED`, or `CONFLICT` may be silently
treated as a valid signature. `VALID_STALE` is not the same as invalid; the
calling playback policy decides whether freshness is required for a specific
license class.

### Operational key rotation

Rotation is an identity-document update under ADR-001:

1. Add a new operational key with explicit roles and `valid_from`.
2. Optionally overlap old and new validity windows to support devices that
   have not yet received the update.
3. Stop using the old key no later than its exclusive `valid_until`.
4. Distribute the complete chain, not only the newest document.

Objects remain signed by exactly one authorized Ed25519 key in the initial
v0.2 profile. Multiple signatures on media objects are deferred; threshold
proofs are used only for identity lifecycle documents. Key rotation never
rewrites or re-signs an existing object.

### Revocation events

A revocation event identifies the identity and key, includes a monotonically
increasing lifecycle-event `sequence`, `issued_at`, `effective_at`, a reason
code, and `previous_event_hash`. It is threshold-signed by recovery keys
authorized in the applicable identity document. Allowed reason codes are
`superseded`, `compromised`, `lost`, and `retired`.

Normative semantics:

- `superseded`, `lost`, and `retired` affect objects whose normative signing
  timestamp is at or after `effective_at`.
- `compromised` MAY declare an earlier `compromise_from`; objects at or after
  that instant become `REVOKED`. This is necessarily retrospective and can
  change a verifier's result after synchronization.
- A revocation cannot make a malformed or unauthorized earlier signature
  valid, and a later identity update cannot erase a revocation event.
- Backdating `effective_at` before the preceding identity document is invalid.

The full event is chained and retained. Deletion lists and unauthenticated
"latest status" responses are not authoritative.

### Offline freshness policy

Core defines verification facts; applications configure freshness durations.
The bundle's `next_update_at` is advisory and cannot force network access.
Profiles MAY require a maximum trust age for commercial time-limited licenses,
but core unrestricted/permanent playback MUST behave as follows:

- If the cached object, asset, license, and locally available signature chain
  are cryptographically valid and not known revoked or conflicted, stale trust
  data MUST NOT prevent playback of unrestricted music.
- The player SHOULD expose `VALID_STALE` and the last synchronization time.
- A newly learned authenticated compromise can change future decisions, but a
  device cannot be expected to enforce information it did not possess.

This is availability-first for unrestricted playback, not a claim that stale
trust is current.

### Legacy v0.1 bindings

A trust bundle can carry a pinned legacy binding containing the exact
`issuer_id`, `key_id`, algorithm, public key, roles assigned by local policy,
and validity metadata. The binding is an external verifier input and MUST NOT
be injected into a v0.1 signed payload. Its provenance must be explicit
(`user-pinned`, `publisher-signed`, or another locally configured source).

Unknown v0.1 keys fail closed. Matching key text without a trusted issuer
binding is insufficient. Existing fixture verification remains possible with
the supplied pinned test key.

## Threat analysis

- Rollback: an attacker can restore an older valid bundle. Persist the highest
  observed identity sequence and bundle timestamp in rollback-resistant local
  state when available; otherwise report possible rollback, not freshness.
- Freeze: an attacker can block new bundles. Offline software cannot solve
  this; surface staleness and avoid claiming current revocation status.
- Equivocation: an identity controller can issue two valid updates at one
  sequence. Preserve both and return `CONFLICT`; publisher gossip can improve
  detection without becoming mandatory consensus.
- Root compromise: threshold recovery reduces single-key risk but cannot help
  if the threshold is compromised. Hardware/offline storage is recommended,
  not protocol-mandated.
- Clock rollback: affects validity intervals. Persist the greatest trusted
  wall-clock observation where possible and expose `CLOCK_UNTRUSTED`; do not
  pretend robust expiry on a compromised device.
- Bundle publisher capture: publisher signatures are provenance hints and
  cannot substitute for identity-chain proofs.
- Privacy: globally stable identity and key IDs permit correlation. Profiles
  should minimize disclosure and allow separate identities for unrelated
  personas.

## Alternatives considered

- Online OCSP-style checks: rejected as mandatory behavior because they break
  offline playback and leak listening activity.
- Short-lived signing certificates only: useful for limiting exposure, but
  still need offline chain distribution and trusted time.
- One global trust-list operator: operationally simple but proprietary and a
  central point of control/failure.
- Blockchain revocation: rejected; it does not solve offline freshness and
  introduces mandatory consensus infrastructure.
- Fail closed whenever trust data is stale: rejected for unrestricted music;
  it turns network availability into DRM.

## Interoperability cases required

1. Merge the same bundle components in different orders and obtain identical
   validated sets and status results.
2. Verify old and new operational keys during an authorized overlap window;
   reject each outside its interval.
3. Reject a key used for the wrong role and a rotation signed below recovery
   threshold.
4. Detect a wrong previous hash, skipped sequence, bundle rollback, and two
   different valid documents at one sequence.
5. Apply `superseded` prospectively and `compromised` from the declared
   compromise instant, including boundary timestamps.
6. Return `VALID_STALE`, not `INVALID`, for a cryptographically valid object
   with an old bundle.
7. Play an unrestricted cached recording under `VALID_STALE`; reject bad,
   revoked, conflicted, unknown-key, and modified-asset cases.
8. Verify every existing v0.1 vector with its original signing bytes and an
   explicit legacy key binding.

## Review record

ADRs 007-010 resolve conflict, freshness, permanent-license, retrospective
compromise, and trusted-time behavior. Media objects remain single-signature;
threshold proofs apply only to identity lifecycle documents. One decision
remains: the exact normative timestamp field used for historical signing-key
authorization for each signed object type. A signer-controlled timestamp alone
may be insufficient; W4 MUST NOT invent this mapping.

