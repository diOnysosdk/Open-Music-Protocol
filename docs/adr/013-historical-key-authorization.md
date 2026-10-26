# ADR 013: Historical signing-key authorization

- Status: Provisionally accepted — protocol owner approved 2026-10-26
- Baseline: `OMP-v0.2-w0-freeze.1`
- Scope: semantic authorization only; no wire or signing-byte change

## Decision proposal

Adopt `docs/historical-key-authorization-v0.2.md` as a normative semantic
amendment with these central rules:

1. Identity documents and lifecycle events derive authority from authenticated
   sequence/hash predecessor order and threshold proofs, not their timestamps.
2. A manifest, license, trust bundle, or time anchor cannot prove historical
   signer authorization with its own signed timestamp.
3. Current role authorization and durable, independently timed prior
   observation are distinct sufficient bases; otherwise historical
   authorization is unknown.
4. Compromise backdating never defeats `compromise_from` and never manufactures
   an `AUTHORIZED_HISTORICAL` result.
5. Cryptographic authenticity, authorization, current trust, entitlement, and
   legal ownership remain separate outputs.
6. Restricted operations fail closed on unknown authorization. Unrestricted
   public playback may use only the narrowly labeled availability behavior
   approved with this amendment.
7. Trust bundles and time anchors cannot bootstrap their own signer authority.

## Compatibility

The amendment changes no JSON Schema, field, identifier, signing domain,
canonical bytes, signature, or v0.1 behavior. It adds semantic evaluation and
new test inputs outside the 42 frozen artifacts.

## Consequences

Portable objects alone cannot always prove historical authorization after a
key ceases to be current. Strong historical results require prior durable
observation evidence. This is intentionally conservative and prevents signed
backdating from being mistaken for trusted time.

## Protocol-owner disposition

Approved 2026-10-26 with mandatory conditions incorporated into the normative
amendment:

- `AUTHORIZATION_UNKNOWN` is a distinct authorization-axis result.
- Exact previously verified and locally pinned unrestricted public content may
  use `PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` only with eligible durable-pin
  evidence.
- TOFU-only pins, altered content, rollback, known compromise/revocation, and
  conflict cannot use the new exception.
- ADR-007 conflict handling and ADR-008 stale-license rules retain precedence.
- The exception grants playback availability only and no other authority.
