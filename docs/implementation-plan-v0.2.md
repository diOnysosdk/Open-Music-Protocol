# OMP v0.2 controlled implementation plan

Status: proposed execution plan; production Rust remains unchanged.

## Readiness position

Recommendation: **GO for controlled implementation, NO-GO for a production
release**. W0 is frozen as `OMP-v0.2-w0-freeze.1`. No workstream may invent
wire behavior to satisfy its tests.

## Non-negotiable boundaries

- Preserve v0.1 parsing, validation, domain separation, signed bytes, and
  fixtures byte-for-byte.
- Dispatch by exact schema version and object type; never retry another
  signing profile after failure.
- Keep cryptographic authenticity, current trust, playback entitlement, and
  legal ownership as separate results.
- Unrestricted public music remains playable offline without authentication
  or required trust refresh.
- Add no mandatory registry, network service, blockchain, payment mechanism,
  DRM, receipt generation, or settlement integration.
- Every protocol rule must trace to frozen normative prose, a schema rule, or
  a named semantic invariant.

## Dependency graph

```text
W0 specification freeze
  ├─> W1 conformance harness and immutable vectors
  ├─> W2 versioned core models/validation
  └─> W3 cryptographic profiles
          W2 + W3 ─> W4 identity/trust
          W1 + W2 + W3 ─> W5 metadata/assets
          W2 + W3 + W4 ─> W6 license/time policy
          W4 + W5 + W6 ─> W7 offline player shell
          all workstreams ─> W8 assurance and release candidate
```

W2 and W3 may proceed in parallel after W0. W4, W5, and W6 can be assigned to
separate agents after their listed dependencies expose reviewed APIs. W7 may
not start from mocks that bypass trust or entitlement decisions.

## Independently assignable Codex workstreams

### W0 — Specification freeze and traceability

Owner profile: protocol architect/editor.

Deliverables:

- resolved ADRs for fork handling, trust freshness, licenses, trusted time,
  localization, and extensions;
- final schema set with stable `$id` values;
- normative semantic-invariant catalog and error-code mapping;
- traceability matrix from each schema field/invariant to positive and
  negative fixtures;
- explicit list of local/deployment policy choices that are not wire rules.

Acceptance criteria:

- no known contradiction among architecture, ADRs, schemas, and vectors;
- all owner-approval items either approved or marked nonblocking local policy;
- all normative MUST/MUST NOT statements have an executable test owner;
- receipts and settlement are explicitly absent from v0.2 scope.

Test ownership: specification validation tests and link/reference checker.

### W1 — Conformance harness and fixtures

Owner profile: interoperability/test engineer.

Depends on: W0.

Deliverables:

- immutable positive and negative fixture corpus;
- deterministic WAV and FLAC generation with provenance/license notice;
- RFC 8785 official edge cases and cross-language expected bytes;
- fixture manifest containing SHA-256, sizes, generator version, and commands;
- CI entry points that never rewrite expected fixtures during verification.

Acceptance criteria:

- regeneration in a clean environment is byte-identical;
- Rust and at least one independent implementation agree on every canonical
  byte string, payload hash, identity commitment, and signature;
- each negative fixture maps to exactly one primary stable error code;
- symlink tests are generated at runtime and cover Windows reparse points or
  record a platform-specific skip with a separate Windows CI owner;
- no private key except conspicuous deterministic TEST-ONLY material exists.

Test ownership: fixture reproduction, schema/vector tests, cross-language JCS,
asset/path test corpus, and v0.1 regression fixtures.

### W2 — Exact version dispatch and v0.2 core models

Owner profile: Rust protocol-model engineer.

Depends on: W0 and stable schemas from W1.

Deliverables:

- frozen `v01` module/API behavior and separate `v02` models;
- duplicate-safe parse-first version/object dispatch;
- schema-equivalent validation plus named cross-field semantic validation;
- structured errors using the frozen error catalog.

Acceptance criteria:

- every v0.1 fixture produces the same result and signing payload as before;
- mixed-version, unknown-version, prohibited-field, duplicate-key, invalid
  Unicode, wrong identifier-kind, and range cases fail closed;
- no generic “try every model” deserialization path exists;
- all public APIs are documented and fuzz targets cover parser entry points.

Test ownership: core unit/property tests, schema parity tests, parser fuzzing,
and version-confusion negative tests.

### W3 — v0.2 cryptographic profiles

Owner profile: cryptography engineer.

Depends on: W0 and cryptographic vectors from W1.

Deliverables:

- typed domain identifiers for all six profiles and identity commitment;
- exact top-level exclusion APIs that cannot remove nested fields;
- verification of threshold proofs without changing single-signature media
  objects;
- test-only APIs for fixture reproduction kept out of production key paths.

Acceptance criteria:

- every published vector verifies and every domain/object swap fails;
- padded base64url, wrong length, unknown algorithm, truncation, malleation,
  and missing excluded member fail;
- private material is zeroized where supported and generated with OS entropy;
- a focused external cryptographic review signs off before release.

Test ownership: canonicalization/domain tests, deterministic vectors,
signature negatives, key-generation tests, and cryptographic fuzz targets.

### W4 — Identity, lifecycle, and offline trust

Owner profile: identity/security state-machine engineer.

Depends on: W2 and W3.

Deliverables:

- self-certifying identity generation and chain validation;
- single-key and optional threshold-recovery proof evaluation;
- lifecycle-event validation, fork detection, rollback detection, and
  historical-authenticity/current-trust separation;
- explicit TOFU `UNVERIFIED` state and atomic local trust-store interface;
- signed bundle validation and deterministic merge.

Acceptance criteria:

- no observation silently promotes TOFU;
- forks and same-sequence conflicts are deterministic under the frozen ADR;
- historical valid signatures remain reportable after current revocation;
- bundle merge order cannot change validated fact sets;
- unknown, unauthorized, revoked, stale, rollback, and conflict states map to
  distinct documented results.

Test ownership: identity/lifecycle chain tests, threshold/recovery matrix,
trust merge/property tests, rollback/fork fixtures, and trust-store crash tests.

### W5 — Metadata and deterministic asset binding

Owner profile: Unicode/filesystem/media engineer.

Depends on: W1, W2, and W3.

Deliverables:

- NFC metadata and versioned role-vocabulary validation;
- portable relative-path validator independent of host path normalization;
- contained, no-symlink package resolution;
- unique asset/path/rank validation and deterministic selection;
- hash/size verification that returns the same open handle used for decoding.

Acceptance criteria:

- non-NFC input is rejected, never rewritten before signature checks;
- traversal, absolute paths, separators, ambiguous encodings, case collisions,
  symlinks/reparse points, and TOCTOU substitution fail;
- exact WAV/FLAC fixtures bind and altered bytes/size fail;
- selection is independent of JSON array and directory enumeration order;
- Linux and Windows filesystem CI pass.

Test ownership: Unicode corpus, portable-path property tests, platform
filesystem integration tests, asset fixture tests, and media-sniff mismatch.

### W6 — License and trusted-time decision engine

Owner profile: authorization/time semantics engineer.

Depends on: W2, W3, and W4.

Deliverables:

- pure `omp-license` evaluator with injected subject, trust facts, and clock
  evidence;
- public unrestricted, permanent subject, and time-limited decisions;
- signed time-anchor validation and monotonic observation persistence;
- explicit separation of protocol-valid decision and user override mode.

Acceptance criteria:

- public unrestricted playback requires neither identity authentication nor
  network freshness;
- interval behavior is exactly `valid_from <= t < expires_at`;
- unavailable/expired/rolled-back time evidence fails time-limited grants with
  its distinct code;
- clock state loss behavior matches the frozen ADR;
- compromised-device limitations are exposed in docs and never called DRM.

Test ownership: decision tables, timestamp boundary/property tests, anchor
chain tests, rollback/state-loss scenarios, and cross-object linkage tests.

### W7 — Minimal offline player shell

Owner profile: application/security-boundary engineer.

Depends on: W4, W5, and W6.

Deliverables:

- headless orchestration state machine and narrow decoder/audio traits;
- local-file discovery with explicit package root;
- bounded decoder isolation and stable user-visible rejection reasons;
- offline-only end-to-end CLI/system test. Receipt and settlement APIs remain
  absent.

Acceptance criteria:

- decoding never starts before required validation, trust, binding, and
  entitlement checks finish;
- verified handle is not closed and reopened by untrusted path;
- unrestricted fixture plays in a network-disabled clean environment;
- invalid signatures, trust conflicts, expired licenses, bad assets, and
  unsupported codecs cannot degrade into a protocol-valid play;
- no telemetry, login, registry URL, or implicit network call exists.

Test ownership: state-machine tests, sandbox/resource-limit tests, end-to-end
offline playback, and decoder fuzzing owned separately from protocol fuzzing.

### W8 — Assurance and release candidate

Owner profile: security/release engineer independent of W2–W7 authors.

Depends on: all workstreams.

Deliverables:

- consolidated threat model and external-review disposition;
- dependency/SBOM and license report;
- reproducible build and signed release artifacts;
- compatibility matrix for Windows/Linux and v0.1/v0.2;
- release readiness record tying every acceptance criterion to evidence.

Acceptance criteria:

- all mandatory external-review findings are closed or accepted by owners;
- format, Clippy `-D warnings`, unit/integration/doc/fuzz/vector gates pass;
- no production artifact contains test private seeds;
- clean offline installation verifies all shipped fixtures;
- protocol owners explicitly authorize the implementation profile.

Test ownership: release CI, reproducibility, secret scanning, SBOM/license
checks, platform matrix, and final regression suite.

## Required CI gates

The implementation branch must expose stable commands for:

1. Rust formatting, Clippy with warnings denied, all targets, tests, and docs.
2. Python schema/contract/vector tests with bytecode/cache disabled.
3. Fixture regeneration followed by a clean-tree/hash equality check.
4. Cross-implementation RFC 8785 and Ed25519 verification.
5. v0.1 signing-payload snapshot equality.
6. Linux and Windows portable-path/symlink tests.
7. Parser/protocol/decoder fuzz smoke tests with separate corpora.
8. Dependency audit, deny policy, SBOM, license, and secret scanning.

## Change-control rules

- A fixture failure does not authorize changing normative behavior. First
  classify the failure as implementation, fixture, schema, or specification.
- Any wire/schema/domain change returns to W0 and requires new vector version.
- Expected error-code changes require ADR/error-catalog review.
- Production code cannot import fixture private seeds or generator modules.
- Workstream agents edit only their assigned modules/tests unless the protocol
  architect explicitly coordinates a cross-cutting change.

