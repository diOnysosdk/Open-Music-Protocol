# OMP Core v0.1 architecture decisions

## Conservative interpretations

- The schemas use one broad identifier regex for all fields, but the prose
  requires references to have the expected object type. Validation therefore
  requires `manifest_id` to begin `omp:manifest:`, `recording_id` to begin
  `omp:recording:`, and so on.
- `title` and `artist` do not exist in `manifest.schema.json`, whose
  `additionalProperties` is false. The CLI does not add them. Human-readable
  metadata requires a future schema revision.
- IDs are registry-assigned. Packaging never synthesizes registry IDs from a
  filename; callers must supply them.
- `inspect` validates structure and semantics but explicitly does not claim
  authenticity. Only `verify`, with a trusted external public-key document,
  reports a valid signature.
- Asset selection is by the supported media type inferred from the local file
  extension. v0.1 does not define filename binding when a manifest contains
  multiple assets of the same media type. Verification succeeds when the file
  matches any signed entry of that type; producers created here emit one asset.
- Receipt chain validation within a single object enforces the defined
  genesis/non-genesis shape. Checking monotonicity, previous-receipt hashes,
  conflicts, and idempotency needs chain context and is intentionally not
  presented as a single-object guarantee.
- The settlement Merkle root is syntax-checked only. It is never computed or
  interpreted because the Merkle profile is explicitly deferred.
- License timestamps are parsed and compared as instants. No current-time
  usability API is exposed because clock semantics and grace policy remain
  unresolved.

## Cryptographic boundary

Signing and verification always operate on:

```text
ASCII("OMP-SIGNED-OBJECT-v0.1") || 0x00 || JCS(unsigned object)
```

Only the top-level `signature` property is removed. Nested properties named
`signature` would remain authenticated. JSON is parsed with recursive
duplicate-key rejection before model conversion. Ed25519 and unpadded
base64url are strictly allowlisted. SHA-256 processing streams file bytes.

Private keys are separate key documents and are never fields in protocol
models. Key generation uses the operating system RNG through `OsRng`.

## Dependency rationale

The workspace uses focused crates: Serde for wire models, `serde_jcs` for RFC
8785 rather than an ordinary sorted serializer, `ed25519-dalek` for Ed25519,
`sha2` for SHA-256, `time` for RFC 3339 parsing, and `rand_core` for OS
randomness. Full JSON Schema runtime machinery is avoided; closed typed models
implement the supplied schemas and the prose invariants directly.

## Unresolved upstream items

The implementation does not claim production readiness because the supplied
specification leaves key distribution/revocation, rights disputes, license
portability, privacy/retention, fraud policy, payment regulation, normalized
license-time behavior, Merkle rules, authenticated requests, and version
migration unresolved. The supplied vectors also contain no matching audio
fixture and explicitly omit the official RFC 8785 tricky-number/Unicode
corpus. Local tests cover representative JCS behavior, while official
cross-language interoperability remains pending those upstream vectors.

