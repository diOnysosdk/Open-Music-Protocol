# ADR 007: Identity forks and pinned unrestricted playback

- Status: Accepted — protocol owner approved 2026-10-26
- Scope: v0.2 identity-chain conflicts and offline playback
- Depends on: ADR-001, ADR-002, ADR-005

## Context

Two different, correctly authorized identity documents can exist at the same
identity sequence. Offline verifiers cannot know which branch is globally
preferred, and OMP has no mandatory registry or consensus service. Treating a
fork as last-writer-wins enables rollback and equivocation. Treating every
newly discovered fork as retroactively fatal would let unavailable coordination
disable unrestricted music that was already pinned and valid offline.

Cryptographic authenticity, local trust, playback permission, and legal
ownership are separate decisions.

## Proposed normative decision

An identity fork exists when two different complete identity-document hashes
for the same `identity_id` and `sequence` each pass cryptographic and threshold
authorization checks. Implementations MUST retain every known branch and MUST
return `OMP_TRUST_CONFLICT`; they MUST NOT pick the newest arrival, timestamp,
lexicographically smallest hash, or bundle publisher.

A local pin records at least:

- the self-certifying `identity_id` and genesis hash;
- the exact accepted branch-tip document hash and sequence;
- the highest lifecycle-event sequence observed for that branch;
- pin origin (`explicit`, `tofu-unverified`, or verified introduction); and
- the time of local observation when trusted time exists.

Discovery of a fork freezes automatic advancement. No key, revocation, or
delegation appearing only after the fork point may be accepted until the user
or an explicitly configured trust policy selects a branch. Selecting a branch
is a new auditable local decision; it does not erase the conflicting evidence
or make the discarded branch cryptographically invalid.

### Playback matrix

1. Unknown identity with conflicting first-contact branches: fail closed with
   `OMP_TRUST_CONFLICT`. TOFU MUST NOT choose a branch automatically.
2. Subject-bound, permanent purchased, or time-limited access under any
   unresolved fork: fail closed with `OMP_TRUST_CONFLICT`.
3. Unrestricted public content already authenticated on the exact pinned
   pre-fork branch MAY continue playing if all of these hold:
   - the manifest, public license, and asset still verify;
   - their signing keys were authorized on the pinned branch at their signed
     protocol times;
   - no revocation known before the fork makes those signatures unauthorized;
   - no post-fork key or entitlement is needed; and
   - the result is surfaced as `VALID_CONFLICTED_PINNED`, never `VALID_FRESH`.
4. Unrestricted content first encountered after conflict fails closed unless
   an explicit local branch selection establishes a pin.

This exception preserves previously established unrestricted playback without
silently resolving identity control. It does not authorize publishing,
licensing, rights claims, updates, or paid access on the conflicted identity.

## Security consequences

- Attackers cannot win by delivery order.
- A malicious controller can still equivocate; offline systems can only retain
  and expose evidence.
- Continuing exact, previously pinned public content limits a conflict-driven
  denial of service but accepts stale branch information.
- User interfaces must not present conflicted identity labels as verified.

## Required tests

- Two valid documents at one sequence produce identical conflict state in
  either arrival order.
- First-contact conflict never creates a TOFU pin.
- Pre-fork pinned unrestricted content plays with
  `VALID_CONFLICTED_PINNED`; altered, newly signed, subject-bound, and expired
  content does not.
- Branch selection is explicit, persisted, and does not delete fork evidence.

## Protocol-owner disposition

Approved 2026-10-26. The narrow `VALID_CONFLICTED_PINNED` exception is
normative exactly as specified above. Every new artifact and every non-public
entitlement still fails closed during an unresolved fork.

