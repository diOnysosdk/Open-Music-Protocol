# ADR 006: Minimal offline player architecture

- Status: Accepted architecture; production implementation remains deferred
- Scope: post-specification implementation; no production player is included

## Context

## Owner resolution (2026-10-26)

Playback receipt creation, submission, receipt chaining, and settlement
integration are deferred in their entirety to v0.3. The v0.2 player consumes
no receipt or settlement APIs.


The player must validate local content entirely offline, reuse the existing
Rust crates, preserve v0.1 verification, and avoid becoming a DRM, account, or
network subsystem. Audio decoding is not protocol verification and should be
isolated from trusted parsing and cryptography.

## Decision

Use a small headless playback library and CLI boundary with these components:

```text
local file + sidecars
        |
        v
strict version dispatcher --> omp-core validation
        |
        v
offline trust store -------> omp-crypto signature verification
        |
        v
manifest/file binding -----> omp-manifest hash + size verification
        |
        v
license evaluator ---------> identity + trusted-time evidence
        |
        v
bounded decoder process ---> audio output adapter
```

### Proposed crate boundaries

- `omp-core`: v0.1 types remain frozen; add separate v0.2 model modules and
  cross-object link validation after specification approval.
- `omp-crypto`: version-specific signing-domain dispatch, key-document and
  trust-bundle verification; no network client.
- `omp-manifest`: deterministic asset binding and byte verification.
- `omp-license` (new): pure license decision engine taking a verified license,
  verified manifest, subject context, and `ClockEvidence`. It performs no I/O.
- `omp-player` (new): local orchestration and playback state machine. Decoder
  and audio-output adapters sit behind narrow traits.
- `omp-cli`: optional `play` command only after protocol review; existing
  commands retain behavior.

### State machine

`Discover -> Parse -> VerifyTrust -> VerifySignatures -> BindAsset ->
EvaluateLicense -> Decode -> Play`, with any validation failure transitioning
to `Rejected`. `Decode` and `Play` never occur before all required protocol
checks succeed. For a v0.2 permanent public/free grant, no network or local
identity lookup is in the path.

Trust bundles, manifests, licenses, and audio files are read from explicit
paths or a user-selected local library. The core player has no registry URL,
telemetry, login, automatic receipt upload, or mandatory update check.

### Decoder isolation

Malformed media is an untrusted input even after its hash is authenticated.
Run decoding with bounded buffers and resource limits. Prefer a memory-safe
Rust decoder; optionally place codec handling in a separate process where the
platform supports it. A manifest media type is a claim and MUST agree with
detected container/codec information before playback.

### Local state

The minimal persistent state is:

- user-selected trust roots and cached signed trust bundles;
- optional subject private keys stored through an OS secret facility;
- optional trusted-time anchor and monotonic-clock metadata;
- user preferences and library paths.

Private keys, secrets, and trust policy MUST NOT be stored in manifests. A
SQLite database is not required; atomic files are sufficient for the minimal
player. Cached state is never a prerequisite for permanent public/free music
when its issuer key is carried through an already user-trusted offline bundle.

## Failure behavior

- Invalid or unknown signatures, unsupported versions, ambiguous asset
  binding, cross-object ID mismatch, and malformed JSON fail closed.
- Expired/not-yet-valid licenses and missing trusted time return distinct
  errors.
- Unsupported codecs report unsupported media; they do not weaken protocol
  checks.
- Revocation information newer than the cached trust snapshot is unknowable
  offline and is reported as trust freshness, not silently fabricated.

## Testing strategy

- Pure decision-table tests for every license policy, boundary timestamp, and
  clock-evidence state.
- V0.1 regression vectors must remain byte-identical and valid.
- Negative tests for wrong recording/license links, key rotation gaps,
  revoked-at-signing keys, unknown issuer, rollback attempts, hash/size
  mismatch, media-type mismatch, and duplicate JSON keys.
- Decoder fuzzing is separate from protocol-object fuzzing.
- An end-to-end offline test runs with networking disabled and a fresh local
  state directory.

## Consequences

The pure evaluator is deterministic and testable. Decoder compromise has a
smaller blast radius. The architecture remains service-neutral. The cost is
additional explicit inputs—trust snapshot, subject context, and clock
evidence—and some time-limited licenses will be unavailable when trustworthy
time cannot be established.

## Implementation review questions

Receipt creation is resolved as v0.3 scope. Crate boundaries, media-sniffing
override behavior, and commercial freshness defaults remain implementation or
deployment review questions.

1. Approve creation of a separate `omp-license` crate rather than extending
   `omp-manifest`.
2. Define whether media sniffing disagreement is always fatal or can be an
   explicit user override outside protocol-valid mode.
3. Set maximum accepted trust-snapshot staleness for subject/time-limited
   grants, or declare it entirely local policy.

