# OMP v0.2 W7 completion report

Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1` plus ADR-013 and ADR-014  
Recommendation: **GO for controlled W7 integration; NO-GO for production release**.

## Completed gaps

W4 now exposes `assess_durable_pin`, which consumes exact manifest, public
license, and asset bindings; opaque authenticated identity/lifecycle facts;
and a `DurablePinStore` platform capability. It checks eligible non-TOFU prior
authorization, branch/genesis/tip hashes, sequence high-water marks, lifecycle
tips, conflicts, revocation, rollback protection, and exact artifact equality.
The opaque result always retains `AUTHORIZATION_UNKNOWN` and only emits
`PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN`. ADR-007 conflict behavior is not
reimplemented or widened.

`MemoryTrustStore` remains non-production and does not advertise rollback
protection outside tests. A production platform must implement authenticated,
atomic, rollback-resistant storage; otherwise pin assessment fails closed.

W7 accepts the opaque pin assessment through W6 without bypassing public
license, recording/license binding, signature, key equality, or W5 media
integrity checks.

Real audio output uses Rodio 0.20 over CPAL on Windows and Linux. `AudioSink`
is the narrow output interface; `LocalAudioSink` streams WAV/FLAC from the
exact verified W5 handle. `play-headless` remains deterministic for CI and the
new `play` command targets the default local device. Device absence and decoder
errors are explicit failures. No network or telemetry code exists.

## Acceptance matrix

| Criterion | Result |
|---|---|
| Exact ADR-013 artifact and pin provenance | Pass |
| TOFU, altered bindings, rollback, revocation | Rejected |
| Conflict remains ADR-007-only | Pass |
| Unknown authorization never upgraded | Pass |
| Opaque W4 result and W6/W7 integration | Pass |
| Headless WAV/FLAC decode | Pass |
| Mock sink receives verified handle only | Pass |
| Real default-device WAV/FLAC backend | Implemented; hardware execution unavailable in automated CI |
| CLI `play-headless` and `play` | Pass |
| Frozen artifacts and v0.1 compatibility | Pass |

## W8 requirements

- Independent review of pin-state capability adapters and crash/rollback
  semantics on each supported platform.
- Hardware audio tests on Windows and Linux, including interruption, device
  loss, format negotiation, and long-stream buffer behavior.
- Linux filesystem CI and privileged Windows junction/race testing.
- Decoder/media fuzzing, dependency audit, SBOM/license review, reproducible
  builds, and secret scanning.
- Review temporary verified-media storage and local data-at-rest policy.

Production release remains NO-GO until W8 assurance and owner release approval.

