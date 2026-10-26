# ADR-001: Self-certifying OMP identities

- Status: Provisionally accepted for normative-draft verification
- Scope: OMP v0.2 identity bootstrap and identifier generation
- Compatibility: additive; v0.1 identifiers and signatures are unchanged

## Context

## Owner resolution (2026-10-26)

Self-certifying OMP party identities are selected; identity creation has no
registry dependency. Ordinary control is represented by one recovery key with
threshold one. Threshold recovery is optional; the recommended initial
profile is two signatures from three distinct recovery keys, but arbitrary
valid thresholds remain conforming. Identity documents use the exact signing
profile in `docs/signing-profiles-v0.2.md`. Legal identity and ownership remain
separate from cryptographic key control.


OMP v0.1 treats `omp:party:<slug>` identifiers and the binding between an
issuer and a signing key as registry policy. That is sufficient for its test
vectors, but it does not let two offline implementations independently create
or authenticate a party without trusting the same registry. Embedding a raw
public key directly in every identifier would remove the registry but would
make root-key rotation impossible. Using a mandatory hosted DID method would
replace one central dependency with another resolution dependency.

The v0.1 lexical profile already accepts lowercase letters, digits, hyphens,
and a 128-character slug. A SHA-256 commitment encoded as lowercase hex fits
that profile, so a decentralized v0.2 identity can coexist with legacy party
IDs without changing any v0.1 bytes.

## Decision

### Two identity classes

OMP v0.2 recognizes two non-interchangeable party identity classes:

1. `legacy`: any valid v0.1 `omp:party:<slug>` identifier. Its key binding is
   supplied by an explicitly trusted legacy resolver or pinned key.
2. `self-certifying-v0.2`: an identifier derived from an immutable genesis
   identity body as specified below.

Consumers MUST NOT infer that a legacy identifier is self-certifying merely
because its slug resembles the new profile.

### Genesis identity body

The identity creator generates at least one Ed25519 root key and SHOULD
generate distinct offline recovery keys using secure OS randomness. The
genesis body is an I-JSON object with no duplicate keys:

```json
{
  "profile": "omp-self-certifying-identity-v0.2",
  "created_at": "2026-10-26T12:00:00Z",
  "root_keys": [
    {
      "key_id": "root-01",
      "algorithm": "Ed25519",
      "public_key_base64url": "..."
    }
  ],
  "recovery": {
    "threshold": 1,
    "key_ids": ["root-01"]
  }
}
```

Arrays are ordered and therefore committed in their stated order. Duplicate
`key_id` or `recovery.key_ids` values are invalid. Every recovery key MUST be
present in `root_keys`, and `threshold` MUST be between one and the number of
distinct recovery keys.

The identifier is:

```text
commitment = SHA-256(
  ASCII("OMP-IDENTITY-GENESIS-v0.2") || 0x00 || JCS(genesis_body)
)
identity_id = "omp:party:sha256-" || lowercase_hex(commitment)
```

The fixed 71-character slug fits the v0.1 lexical profile. The hash does not
assert a human name, legal personhood, ownership, or authority; it commits to
the root-of-trust material only.

### Identity document

An identity document carries `identity_id`, the complete genesis body, a
monotonic `sequence`, `previous_document_hash`, operational keys, and one or
more root/recovery proofs. Operational keys declare:

- a locally unique `key_id`;
- `algorithm`, initially only `Ed25519`;
- unpadded base64url public-key bytes;
- a nonempty set of roles from `manifest`, `license`, `rights`,
  `trust-bundle`, `time-anchor`, and `identity-update`;
- inclusive `valid_from` and optional exclusive `valid_until` timestamps.

The genesis document has `sequence = 0` and `previous_document_hash = null`.
Every update increments the sequence by exactly one and refers to the SHA-256
of the RFC 8785 canonical complete previous document, including its proofs.
Identity-document signing uses a new, type-specific domain separator:

```text
ASCII("OMP-IDENTITY-DOCUMENT-v0.2") || 0x00 || JCS(unsigned document)
```

Only top-level `proofs` is excluded. Each proof identifies a root or recovery
key. Genesis requires the configured threshold of genesis recovery keys.
Updates require the threshold declared by the immediately preceding valid
document. An operational key alone cannot replace roots or recovery policy.

An implementation MUST recompute `identity_id` from `genesis_body`, validate
the complete document chain, reject forks at the same sequence, and require
the object-signing key to have the correct role and validity at the signed
object's protocol timestamp. Objects with no normative issuance timestamp
cannot use time-scoped keys until their schema defines one.

### Human-readable identity data

Names, artist credits, URLs, avatars, and legal assertions are deliberately
not part of the identity commitment. They belong in signed metadata or
credentials so they can change without changing identity. Implementations
MUST present the identifier or a locally verified label and MUST NOT treat a
self-asserted display name as unique.

## Compatibility rules

- Existing v0.1 JSON remains validated and signed with
  `OMP-SIGNED-OBJECT-v0.1\0`; no identity document is inserted into or removed
  from its signed payload.
- A v0.2 verifier MAY verify a v0.1 object using a pinned legacy public-key
  record. It MUST NOT silently resolve a different key because a v0.2
  identity document happens to mention the same text identifier.
- V0.2 objects use their v0.2 schema and signing domain. Re-serializing a v0.1
  object as v0.2 is migration by creation of a new signed object, not an
  in-place upgrade.
- External DID identifiers MAY appear as signed aliases or credentials, but
  resolution of a particular DID method is never required for core playback.

## Security consequences

- Collision resistance depends on SHA-256 and correct JCS implementation.
- Loss of all threshold recovery keys makes the identity permanently
  non-updatable. Compromise of the threshold can take over future updates.
- Forks cannot be globally prevented without coordination. Offline verifiers
  can detect conflicting documents they possess but cannot prove they have
  seen every branch.
- The first obtained genesis body is self-authenticating against the
  identifier, but distribution authenticity still depends on the user
  obtaining the intended identifier through an independent channel.
- Root keys should remain offline; routine media objects use scoped
  operational keys.

## Alternatives considered

- Mandatory central registry: rejected because it violates decentralized and
  offline requirements.
- Mandatory `did:web`: rejected because resolution depends on DNS, HTTPS, and
  continued hosting.
- Mandatory `did:key`: simple and interoperable, but permanently binds the
  identity to one root key and does not itself define rotation.
- Blockchain-backed identifiers: rejected as unnecessary consensus and
  operational coupling.
- Random UUID party IDs: decentralized generation but not self-authenticating.

## Interoperability cases required

1. Two implementations derive the same identity ID from differently indented
   or property-ordered genesis JSON.
2. Changing one root-key byte changes the identity ID.
3. Duplicate keys, padded base64url, invalid recovery thresholds, and unknown
   algorithms fail.
4. A valid sequence-1 update verifies against sequence 0; skipped sequences,
   wrong previous hashes, insufficient proofs, and forks are rejected or
   reported as conflicts.
5. A manifest key with only the `license` role cannot sign a v0.2 manifest.
6. The existing v0.1 fixtures remain byte-for-byte verifiable with their
   original domain separator and pinned test key.

## Review record and remaining questions

Items 1–3 below are resolved by the owner decision and exact signing profile.
Items 4–5 remain open.

1. Approve the `omp:party:sha256-<hex>` profile rather than adopting a
   standards-track DID as the canonical identifier.
2. Approve SHA-256 lowercase hex and the exact genesis/domain-separator bytes.
3. Approve threshold recovery semantics and whether recovery keys must be
   distinct from ordinary root keys.
4. Decide the normative timestamp field used to evaluate key validity for
   each signed object type.
5. Decide whether identity forks are always fatal or can be surfaced for
   explicit user resolution in non-rights-critical playback.

