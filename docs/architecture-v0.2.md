# OMP Protocol v0.2 — Identity, Metadata and Offline Playback

**Status:** frozen controlled-implementation architecture for
`OMP-v0.2-w0-freeze.1`. Production release remains prohibited until the
independent assurance requirements are satisfied.

## 1. Scope and invariants

OMP v0.2 adds decentralized identity, signed descriptive metadata,
deterministic asset binding, offline trust lifecycle documents, explicit
offline license semantics, and a minimal offline player boundary. It does not
add a registry, blockchain, cryptocurrency, payment rail, DRM system, rights
adjudication service, or mandatory network dependency.

The following invariants are non-negotiable:

1. Every valid v0.1 object remains valid under the unchanged v0.1 validator.
2. A v0.1 signature is always verified with
   `OMP-SIGNED-OBJECT-v0.1 || 0x00`; its bytes and meaning never change.
3. Every v0.2 signed object is a distinct closed wire shape with
   `schema_version: "0.2"` and its exact type-specific signing domain from
   `docs/signing-profiles-v0.2.md`. No generic v0.2 signing domain exists.
4. Dispatch is exact and fail-closed. An unknown version, mixed-version
   object, undeclared field, algorithm mismatch, duplicate key, or
   failed signature is rejected; a verifier never retries under another
   version.
5. Descriptive metadata and identity identifiers are not evidence of
   copyright ownership, licensing authority, or a human's legal identity.
6. Unrestricted music remains playable from locally verifiable artifacts
   without network authentication.

## 2. v0.1 audit and compatibility boundary

The authoritative v0.1 bundle uses closed Draft 2020-12 schemas and requires
`schema_version` to equal `0.1`. The Rust implementation mirrors this with
closed Serde models, expected-kind identifier checks, recursive duplicate-key
rejection, Ed25519-only signatures, exact top-level signature removal, RFC
8785 canonicalization, and byte-exact SHA-256/size checks.

Consequently, adding metadata fields to a v0.1 manifest would invalidate both
schema validation and its signature. v0.2 uses new schemas and models rather
than widening the v0.1 model. Implementations must retain both validators.

Relevant unresolved v0.1 topics promoted into this proposal are key
distribution and revocation, registry-assigned identifiers, metadata,
multi-asset selection, offline license time semantics, and player policy.
Receipt eligibility, settlement Merkle rules, payments, and rights disputes
remain outside v0.2.

## 3. Versioning and extension strategy

An implementation first performs duplicate-safe I-JSON parsing and reads only
the top-level `schema_version` for dispatch. It then applies exactly one
version-specific closed schema, semantic validator, signing domain, and trust
policy. Version dispatch itself never canonicalizes or mutates the object.

OMP v0.2 defines no extension envelope. Every schema is strictly closed and
every undeclared member, including `extensions` or `critical_extensions`, is
rejected as `OMP_SCHEMA_INVALID`. ADR-012 is deferred to a future version.

No v0.2 artifact may claim to be a lossless v0.1 object. A migration creates a
new object with a new identifier, timestamp, v0.2 signature, and an optional
authenticated `supersedes` reference to the SHA-256 of the complete v0.1
object. The original stays available for independent verification.

## 4. Decentralized identity

The identity design is local-first and service-independent:

- Identity generation uses secure OS randomness and Ed25519.
- A self-certifying identity identifier is derived deterministically from the
  genesis identity key material; generation needs no registry or network.
- Operational key identifiers are opaque and scoped by their containing
  identity document. External DIDs may be authenticated aliases, but core
  playback does not require a DID resolver.
- Identity documents, rotation proofs, and revocation statements are signed,
  canonical JSON artifacts that can travel with music or be imported from any
  transport.
- Verification distinguishes key control from authorization. A self-signed
  identity begins as `untrusted` unless explicitly pinned, introduced by an
  already trusted identity, or allowed by local policy.

Rotation preserves the stable identity identifier through a hash-linked,
strictly sequenced update chain authorized by the current key and acknowledged
by the successor key. Emergency recovery and compromise behavior are approval
items because availability and attacker lockout pull in opposite directions.

The detailed identity and trust decisions live in the ADRs under `docs/adr/`
and the frozen identity schemas.

## 5. Metadata model

Metadata is signed but expressly descriptive. The v0.2 manifest carries a
structured `metadata` object containing:

- a required nonempty recording title;
- ordered artist credits, each with a display name and optional party identity;
- ordered contributors with display name, optional identity, and one or more
  normalized role tokens;
- optional release information: title, release identity, label credit,
  release date, disc number, and track number.

Ordering is presentation-significant and preserved by JSON arrays. Display
names are Unicode strings and must be nonempty after the protocol's chosen
whitespace rule. They are not identity keys. Role tokens come from the closed
vocabulary identified by `role_vocabulary`; an unknown token or vocabulary is
rejected rather than silently reinterpreted. A future vocabulary version can
extend the terms without changing existing signed meanings.

## 6. Deterministic asset-to-file binding

Every v0.2 asset entry has a unique `asset_id`, exact `sha256`, exact
`size_bytes`, allowlisted `media_type`, portable `relative_path`, playback
`role`, and unique `selection_rank`. A relative path is UTF-8 NFC, `/`
separated, case-sensitive, and package-root-relative. Empty, `.` and `..`
segments, backslashes, control characters, colons, absolute paths, and
segments ending in space or `.` are prohibited.

Binding is deterministic:

1. Hash and count the candidate file bytes without metadata normalization.
2. Resolve each signed relative path beneath an explicitly selected package
   root without allowing symlink escape.
3. Select the entry whose `relative_path` equals the candidate's normalized
   package-relative path byte-for-byte; duplicate paths are invalid.
4. Require its allowlisted media type to agree with the declared entry. File
   extensions are hints only and never security inputs.
5. Require exact size and SHA-256 equality. Playback chooses the verified,
   supported, non-preview entry having the lowest unique `selection_rank`.

Relocation of a complete package is allowed because paths are relative.
Escaping symlinks, URL fetching, and filename guessing are outside the core
verifier.

## 7. Offline trust model

The player maintains a local trust store containing explicitly trusted
identity roots, verified identity-update chains, revocations, and monotonic
observation state. Trust bundles are portable signed collections and may be
distributed by removable media, application packages, local transfer, or any
optional network transport. No transport is privileged by the protocol.

Verification separates four outcomes: cryptographically valid, trusted for a
specific role, revoked/invalid at evaluation time, and indeterminate because
required offline evidence is unavailable. Paid or identity-restricted access
fails closed on indeterminate trust. An unrestricted work whose manifest and
bytes verify remains playable; lack of fresh network state is not a denial
condition.

Rotation and revocation artifacts are monotonic and hash-linked. A verifier
must reject rollback to a lower sequence or a conflicting artifact at the
same sequence. Offline revocation has an unavoidable staleness window; trust
bundles therefore carry an issued time and optional next-update time, and
local policy records when each bundle was last observed. No protocol text may
claim immediate global revocation while offline.

## 8. Offline license behavior

v0.2 makes access duration explicit:

- `unrestricted`: no subject authentication or expiry; valid local manifest,
  trust evidence, and matching asset are sufficient.
- `permanent`: a signed subject license has `valid_from` and no expiry. It
  remains usable offline unless a locally available, valid revocation applies.
- `time_limited`: a signed subject license has `valid_from`, `expires_at`, and
  an offline evaluation policy. Playback is allowed only within that interval
  under the trusted-time rules.

Wall-clock rollback cannot be made tamper-proof on a compromised general
purpose device. The minimal player stores the maximum trusted wall-clock time
and monotonic elapsed-time anchor it has observed. It rejects time-limited
licenses when time moved backward beyond an approved tolerance, state was
lost, expiry passed, or the required trust evidence is stale. It never denies
an `unrestricted` work merely because clock or revocation freshness is
indeterminate.

## 9. Minimal offline player architecture

The player is a thin application shell around existing and proposed pure
libraries:

```text
local files
  -> duplicate-safe parser / exact version dispatcher (omp-core)
  -> JCS, signatures, hashes (omp-crypto)
  -> manifest + deterministic binding (omp-manifest)
  -> identity chain + local trust policy (proposed omp-identity)
  -> license + trusted-time decision (proposed omp-license)
  -> format decoder -> audio output (player adapter boundary)
```

The verification and policy pipeline completes before a decoder receives the
file. Decoders and audio backends do not parse manifests or private keys. The
core libraries perform no network calls. Trust-store updates and optional
artifact acquisition are separate adapters. Private keys are not required for
playback and never enter manifests or licenses.

## 10. Interoperability suite

The frozen vector set includes:

- unchanged acceptance of every v0.1 fixture using the v0.1 domain separator;
- valid v0.2 manifest, identity genesis/update, trust bundle, unrestricted
  license, permanent license, and time-limited license vectors;
- byte-identical JCS and signing payload outputs in Rust and TypeScript,
  including official RFC 8785 numeric and Unicode cases;
- property-order and whitespace invariance;
- negative vectors for duplicate keys, undeclared extension fields, mixed
  version/domain, malformed DIDs, unauthorized rotation, rotation fork and
  rollback, revoked keys, stale bundles, filename traversal/case ambiguity,
  duplicate binding names, wrong size/hash, metadata spoofing, expiry boundary,
  clock rollback, and removal of authenticated fields.

Each vector directory contains the input JSON, expected canonical bytes or
their lowercase SHA-256, expected signing payload, detached trusted inputs,
expected outcome/error code, and any exact asset bytes. Private fixture keys
are test-only and must not ship in production binaries.

## 11. Migration rules

1. Keep all v0.1 files byte-for-byte and verify them with v0.1 code.
2. Create a new v0.2 identity locally or select an already trusted identity.
3. Re-hash the original audio; do not copy a hash without reading the bytes.
4. Create a v0.2 manifest with explicit portable relative paths and metadata.
5. Optionally set `supersedes.object_sha256` to the hash of the complete v0.1
   manifest and retain its identifier as informational provenance.
6. Issue a v0.2 license with explicit access duration; do not reinterpret a
   missing v0.1 expiry as a new v0.2 authorization.
7. Sign each new object with the v0.2 domain and distribute required identity
   and trust evidence alongside it.
8. During transition, dual-version software verifies each object only under
   its declared version. It never upgrades during verification or copies a
   v0.2 signature into a v0.1 envelope.

## 12. Security risks and tradeoffs

- Self-certifying identifiers prevent identifier/key substitution but do not
  verify legal names, rights, or reputation.
- Offline revocation is eventually observed, never instantaneous.
- Dual-signature rotation improves continuity but can prevent recovery after
  total key loss; recovery keys improve availability but enlarge attack scope.
- Portable filenames improve determinism but require normalization and
  collision checks before filesystem access.
- Signed display metadata can still impersonate an artist unless local trust
  binds the credited identity and name.
- Permanent licenses are copyable bearer artifacts unless subject binding is
  meaningful; v0.2 deliberately does not introduce DRM.
- Time-limited offline enforcement is advisory on compromised devices and must
  not be represented as technically absolute.
- Trust-on-first-use is decentralized and usable but vulnerable on first
  contact. Explicit fingerprint comparison is stronger but less convenient.
- Bundled trust material improves offline availability but may be stale or
  selectively withheld.

## 13. Owner decisions and remaining review blockers

All internal W0 protocol decisions are resolved in
`docs/decision-register-v0.2.md`. ADRs 007-011 are accepted. ADR-012 is
deferred, so schemas remain closed. The reproducible WAV/FLAC fixtures and
negative interoperability cases are frozen with the schemas and signing
vectors.

No remaining protocol-owner decision blocks controlled W1/W2/W3 work. The
cross-object timestamp used for historical signing-key authorization must be
approved before W4 identity/trust implementation. Production release also
remains blocked on the independent
cryptographic, schema, identity-state-machine, Unicode/filesystem, privacy,
legal, supply-chain, and cross-platform assurance listed in
`docs/external-review-checklist-v0.2.md`.

## 14. Phased implementation plan

### Phase 0 — review and freeze

Complete as `OMP-v0.2-w0-freeze.1`. No production code changed in this phase.

### Phase 1 — versioned parsing and vectors

Add explicit `0.1`/`0.2` dispatch without modifying v0.1 models. Implement
v0.2 models, schema-equivalent validation, domain separation, and all positive
and negative conformance vectors. Gate on Rust/TypeScript JCS equality.

### Phase 2 — identity and trust

Implement key generation, identity documents, rotation/revocation chain
validation, portable trust bundles, and a local trust-store interface. Add
rollback/fork and stale-evidence security tests.

### Phase 3 — metadata and asset binding

Implement v0.2 manifest creation/inspection, Unicode and role validation,
portable binding-name checks, and exact deterministic file selection. Retain
v0.1 verification unchanged.

### Phase 4 — licenses and policy

Implement unrestricted, permanent, and time-limited decisions with an
injectable clock and persistent monotonic observation state. Test boundaries,
rollback, state loss, and offline revocation staleness.

### Phase 5 — minimal player shell

Add local library scanning, verification/policy orchestration, decoder and
audio-output adapters, and clear user-visible failure reasons. Keep networking
optional and outside the core. Perform threat modeling, fuzzing, cross-platform
filesystem tests, and an external security review before any production claim.

