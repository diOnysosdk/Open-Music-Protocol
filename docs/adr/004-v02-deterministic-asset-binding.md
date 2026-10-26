# ADR 004: Deterministic manifest-to-file binding

- Status: Provisionally accepted for normative-draft verification
- Date: 2026-10-26
- Decision owners: OMP protocol owners

## Context

## Owner resolution (2026-10-26)

The strict portable-path profile is accepted. Resolution is relative to an
explicit package root, uses `/` separators and NFC, rejects ambiguous or
noncanonical encodings, and MUST reject every symlink or reparse-point traversal
for the v0.2 core profile—even when the eventual target appears inside the
root. Verification and decoding SHOULD use the same already-open file handle.


The v0.1 manifest authenticates asset bytes by SHA-256 and size but does not
bind entries to portable package paths or define deterministic selection among
multiple playable encodings. Selecting the first media-type match depends on
array order and cannot distinguish two files with the same media type.

## Proposed decision

Every v0.2 asset entry contains:

- `relative_path`: a signed path in the OMP portable-path profile;
- `role`: `primary`, `alternate`, or `preview`;
- `selection_rank`: a nonnegative integer preference; and
- the existing `asset_id`, `media_type`, `sha256`, and `size_bytes` fields.

The portable-path profile is UTF-8 Unicode NFC, `/` separated, relative to the
manifest package root, case-sensitive, and at most 1024 UTF-8 bytes. Empty,
`.` and `..` segments, backslashes, control characters, colon, absolute paths,
and segments ending in space or `.` are prohibited. Filesystem resolution must
reject symlinks or any resolution escaping the selected package root. Schema
patterns approximate this profile; implementations perform the normative byte
length, NFC, segment, and containment checks.

Within one manifest, `asset_id`, `relative_path`, and `selection_rank` MUST
each be unique and exactly one asset MUST have role `primary`.

### Binding algorithm

1. Parse JSON with duplicate-key rejection and validate the versioned schema.
2. Verify the v0.2 signature before using any path.
3. Validate every portable path, then resolve it beneath an explicitly chosen
   package root without following an escaping symlink.
4. A candidate file binds only to the entry whose case-sensitive
   `relative_path` equals its normalized package-relative path.
5. Stream the file once and require both exact `size_bytes` and lowercase
   SHA-256 equality. Extension and media-type sniffing are advisory and never
   replace the signed digest.
6. For playback, filter to supported media types, non-preview roles, present
   paths, and successfully verified bytes. Choose the smallest
   `selection_rank`; uniqueness makes the result deterministic. If none bind,
   fail closed. A preview is selected only after an explicit preview request.

Array order has no selection semantics. Moving or renaming a packaged file
requires a newly signed manifest even when bytes are unchanged. Copying the
entire package without changing relative paths does not.

## Compatibility

This rule applies only to v0.2. The v0.1 behavior remains byte-hash matching
without path binding and must not be retroactively changed.

## Security consequences

- Signed relative paths prevent ambiguous same-type selection.
- Root containment and symlink handling prevent path traversal and time-of-
  check/time-of-use substitution.
- SHA-256 and size verification remain authoritative; filenames are not.
- A player should open a verified file handle and decode from that same handle,
  rather than verify and reopen by path.

## Alternatives rejected

- Binding only by filename: collisions and directory ambiguity.
- Selecting by array order: fragile under transformations and underspecified.
- Binding only by content hash: deterministic for bytes but cannot identify
  which package file is intended when duplicate content or sidecars exist.
- Mandatory codec negotiation identifiers in v0.2: useful, but codec profiles
  need separate interoperability work.

## Review record

Global selection-rank uniqueness, total symlink rejection, case-sensitive NFC
paths, and exactly one primary asset are selected by the owner decision and
draft schema/semantic rules.

1. Whether `selection_rank` must be globally unique or only unique among
   playable non-preview assets.
2. Whether symlinks are always prohibited or permitted when their fully
   resolved target remains beneath the package root.
3. Whether signed paths should be case-sensitive on all platforms (proposed)
   or use a restricted lowercase ASCII path profile.
4. Whether exactly one `primary` asset is required when a manifest contains
   only previews.

