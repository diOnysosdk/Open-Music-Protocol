# OMP v0.2 W7 secure offline player report

Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1` plus ADR-013 and ADR-014  
Recommendation: **CONDITIONAL GO for headless controlled integration; NO-GO for production release**.

## Implemented

`omp-player` orchestrates W3-authenticated manifests, opaque W4 identity facts,
W4 role assessment, W6 license entitlement, W5 deterministic media binding,
and Symphonia WAV/FLAC decoding. Decoding consumes the exact private verified
W5 handle and never reopens a package pathname. Packet and decoded-frame limits
fail closed. The pipeline contains no network code.

W4 provenance was hardened: `VerificationResult` fields are private and
`assess_signer` can create a successful result only from opaque W2/W3-validated
identity/lifecycle facts. W6 imports that result through
`TrustAssessment::from_w4`. W7 additionally proves the supplied Ed25519 key is
the authenticated operational key and independently assesses both `manifest`
and `license` roles.

The `omp-player` binary provides `verify` and `play-headless` commands with an
explicit package root, manifest, license, identity, and public key. Both run
fully offline; `play-headless` decodes without requiring speakers.

## Acceptance matrix

| Criterion | Result |
|---|---|
| W2/W3 manifest and license verification | Pass |
| Opaque W4 provenance and role checks | Pass |
| W6 recording/license binding and permit | Pass |
| W5 exact verified handle transfer | Pass |
| WAV and FLAC headless decoding | Pass |
| Packet/frame resource limits | Pass |
| Revocation denied before decoder construction | Pass |
| Fully offline deterministic FLAC demonstration | Pass |
| Tamper, media, entitlement and time negatives | Covered across W3-W6 suites |
| Real speaker output backend | Not implemented |
| ADR-013 pinned-unknown end-to-end W7 case | Blocked by incomplete W4 current-status provenance model |
| Linux and privileged Windows stress CI | Outstanding |

## Integration limitation

The frozen manifest and public-license crypto vectors have different
`license_id` values, so the end-to-end test deterministically re-signs a
test-only matching public license using the published test seed. Frozen vectors
remain unchanged.

W4 now prevents direct construction of successful results, but its current
`assess_signer` model cannot yet produce the exact ADR-013 pinned-public
`AUTHORIZATION_UNKNOWN` state for a formerly demonstrated key without a new
opaque durable-pin assessment API. W7 does not invent that state; the affected
exception remains blocked. Ordinary authorized, revoked, license, media, and
decoder paths are operational.

## Remaining work

- Add a reviewed opaque W4 durable-pin assessment API for the ADR-013 W7 path.
- Add an optional real audio-device sink with platform resource/isolation
  review. Headless decoding is the only current output backend.
- Run Linux descriptor-relative filesystem and privileged Windows junction/
  race CI.
- Add decoder fuzzing and malformed-media corpus testing under resource limits.
- Complete W8 independent cryptographic, filesystem, decoder, and platform review.

No GUI, streaming, registry, blockchain, payments, receipts, telemetry, or
recommendation system was implemented.

