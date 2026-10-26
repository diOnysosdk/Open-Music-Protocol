# OMP Protocol v0.1 — Implementer Draft

**Status:** experimental, NOT an approved interoperability standard or security-audited production protocol.

## Wire format

- UTF-8 JSON, I-JSON compatible. Reject duplicate keys and invalid Unicode. JSON Schema Draft 2020-12; JSON Schema alone is insufficient for cross-field checks.
- IDs are opaque and case-sensitive, with the `omp:<kind>:<slug>` lexical profile in the schemas. IDs are registry-assigned; collision management remains a registry concern.
- Timestamp values MUST be RFC 3339 with explicit timezone. Normalize to UTC for semantic comparisons; signed original bytes remain unchanged.
- All signatures use Ed25519, base64url without padding. `signature` is excluded **at top level only** from the signed payload. `key_id` and algorithm are authenticated through trusted issuer/key lookup and strict algorithm allowlisting; they are not embedded in the signed payload in v0.1.
- Signing bytes: ASCII `OMP-SIGNED-OBJECT-v0.1` followed by one NUL byte (`00`), followed by RFC 8785 JCS UTF-8 bytes of the unsigned JSON object. Never use a generic sorted-JSON serializer for production signing.
- Signing keys are bound by registry policy to object issuer (or to a device for receipts), scoped to role and validity interval. Key revocations and offline verification policy are deployment concerns, not solved by Ed25519 itself.
- `recording_id` identifies recording independent of encoding. The exact asset bytes are checked against `sha256` and `size_bytes`. No audio bytes on-chain.

## Semantic invariants (MUST be tested in addition to JSON Schema)

1. All identifiers reference the expected object type; references resolve to the same recording where applicable.
2. `splits` basis points sum to exactly 10000. Reject duplicated recipients.
3. `valid_from < expires_at` if expiry exists; expired offline licenses are unusable unless a separately specified grace policy exists. Free and purchased licenses may omit expiry.
4. `period_start < period_end`, `deductions_minor <= gross_minor`, and sum of allocated amounts equals gross minus deductions. Amounts are decimal strings to avoid integer overflow/float rounding across languages.
5. The referenced agreement version is immutable once used for settlement.
6. Receipt sequencing is monotonic per installation chain; first receipt has `sequence=0` and null previous_hash; subsequent receipts reference SHA-256 of canonical **complete previous receipt** (including its signature) and increment by one. Duplicate `receipt_id` with different content is a conflict; exact retransmission is idempotent.
7. Receipts are not proof of actual human listening. Fraud policy and eligible-play definitions are a separate normative profile, still TBD.
8. Metadata is not copyright evidence. Legal ownership, licensability and split agreements need additional verification/dispute process.
9. All ledger checkpoints and Merkle tree rules are **deferred**. `receipt_merkle_root` currently is a fixture-only placeholder and MUST NOT be treated as interoperably computable until the Merkle profile is specified.
10. Audio with an unrestricted/free license must remain locally playable without a registry connection. Offline paid subscription expiry cannot be robustly enforced on a compromised or clock-rolled-back consumer device.

## API error contract

Response body matches `schemas/api-error.schema.json`. Recommended statuses: `400 OMP_SCHEMA_INVALID`, `401 OMP_UNAUTHENTICATED`, `403 OMP_FORBIDDEN`, `404 OMP_NOT_FOUND`, `409 OMP_DUPLICATE_CONFLICT`, `422 OMP_SIGNATURE_INVALID`, `422 OMP_LICENSE_INVALID`, `422 OMP_RIGHTS_CONFLICT`, `429 OMP_RATE_LIMITED`, `503 OMP_REGISTRY_UNAVAILABLE`. Errors are opaque about sensitive internal state; include request ID. Exact mapping is provisional.

## Interoperability requirements

- Independent implementations must accept valid fixture objects, validate the exact signing bytes, and verify Ed25519 signatures with `examples/test-public-key.json`.
- Changing property order or whitespace without changing value MUST retain signature validity. Changing any signed field MUST fail verification.
- Wrong public key, signature truncation, altered issuer binding, unknown key, invalid asset hash, duplicated JSON keys, non-JCS numeric corner cases, and prohibited fields MUST fail safely.
- Offline playback: cached manifest, matching local audio and valid license, no network; then reconnect and idempotently submit receipts.
- A Rust/TypeScript round-trip vector must produce byte-identical JCS outputs and identical signed payload bytes. Add official RFC 8785 tricky-number / Unicode vectors before declaring spec interoperable.

## Explicitly unresolved before production

Key distribution/revocation during offline periods; rights verification and appeals; license portability across devices; consent, retention and privacy controls; anti-fraud eligibility policies; payment provider and regulatory arrangements; normalized timestamp semantics for license checks; ledger Merkle profile and consensus selection; authenticated request envelope; version negotiation and future migrations.
