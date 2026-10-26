# OMP v0.2 W6 offline licensing and trusted-time report

Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1` plus ADR-013 and ADR-014  
Recommendation: **CONDITIONAL GO for controlled integration; NO-GO for production release**.

## Implemented

The new `omp-license` crate provides opaque W2/W3-authenticated license and
time-anchor types, imports the independent W4 result axes, evaluates offline
entitlement, and returns a non-deserializable/non-constructible
`PlaybackPermit`. It implements public permanent, subject permanent,
time-limited purchase, and subscription behavior without network access.

Time-limited evaluation requires the complete conservative interval to satisfy
`valid_from <= lower <= upper < expires_at`. Ordinary wall clocks and signed
license timestamps are never accepted as time evidence. Signed anchors require
separate W4 authorization, verified identity trust, active status, fresh trust,
monotonic continuity, maximum-age compliance, sequence/hash progression, and
durable lower-bound progression.

`TrustedTimeStore` is the explicit platform persistence boundary. Its contract
requires authenticated atomic storage and genuine rollback resistance; the
crate deliberately does not claim those properties from hashes or ordinary
files. Corrupt checkpoints and regressing anchors fail closed.

## Decision matrix

| Case | Result |
|---|---|
| Public permanent, authorized, stale/unknown freshness | Authorized offline without clock |
| Exact ADR-013 pinned public exception | Explicit `PinnedAuthorizationUnknown` permit |
| Permanent subject, approved ADR-008 stale pin | Explicit `ValidStale` permit |
| Subscription/time-limited without fresh trust or time | Denied |
| Interval before start | `OMP_LICENSE_NOT_YET_VALID` |
| Interval touching/crossing expiry | `OMP_LICENSE_EXPIRED` |
| Subject or recording/license mismatch | Denied with distinct binding error |
| Revoked/conflicted/unknown authority | Denied |
| Anchor rollback, replay, monotonic reset, corruption | Denied |

## W7 contract

W7 must bind `PlaybackPermit::recording_id` and `license_id` to the
authenticated manifest and the W5 `VerifiedMedia` pipeline before transferring
the W5 verified handle to a decoder. Permit kinds preserve ordinary,
`VALID_STALE`, and `PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` outcomes. W7 cannot
construct or deserialize a permit and must not convert errors or user override
modes into one.

## Remaining assurance and integration work

- A production W4 end-to-end assessment constructor remains required. W6
  imports `VerificationResult`, but W4's current public result container still
  needs independent provenance hardening before hostile in-process callers are
  considered out of scope.
- Implement and certify `TrustedTimeStore` adapters using platform secure
  storage/monotonic facilities. Ordinary JSON/filesystem storage is insufficient.
- Exercise platform clock reset, reboot, backup restore, cloning, crash
  consistency, and corrupted-store scenarios in platform CI.
- Fuzz license/time-anchor parsing and interval arithmetic.
- Independent cryptographic, authorization, and trusted-time review remains mandatory.

No W7 player, DRM, payments, settlement, registry, telemetry, or network
service was implemented.

