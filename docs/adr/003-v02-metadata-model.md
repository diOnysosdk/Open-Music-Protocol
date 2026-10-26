# ADR 003: Structured descriptive metadata in v0.2

- Status: Accepted for `OMP-v0.2-w0-freeze.1`
- Date: 2026-10-26
- Decision owners: OMP protocol owners

## Context

## Owner resolution (2026-10-26)

Applicable metadata strings and portable paths MUST be Unicode NFC at
semantic validation. Signed input is never normalized by a verifier: a
non-NFC value is rejected, not rewritten. Contributor roles use the closed,
versioned `omp-contributor-roles-v0.2` vocabulary documented in
`docs/contributor-roles-v0.2.md`.


The v0.1 manifest is closed with `additionalProperties: false`; adding `title`
or `artist` would make a v0.1 object invalid and would change its signed
payload. Metadata is descriptive and is not evidence of authorship, ownership,
or entitlement.

## Proposed decision

Create a distinct `schema_version: "0.2"` manifest schema. A v0.2 manifest has
a required `metadata` object containing:

- a recording title, optional subtitle and version label;
- ordered artist credits, each with a display name and optional identity
  reference and join phrase;
- contributors with stable manifest-local credit IDs, display names, optional
  identity references, and one or more machine-readable role tokens; and
- optional structured release information.

Artist-credit array order is presentation order. `join_phrase` is literal text
following that credit, allowing presentations such as “A feat. B & C” without
parsing a single artist string. Contributor order has no legal meaning.

All human-readable strings MUST be valid Unicode, nonempty after trimming for
validation, and preserved byte-for-byte as JSON string values for signing.
Implementations MUST NOT trim or normalize signed data. Producers SHOULD emit
Unicode NFC; consumers MAY warn about non-NFC but MUST verify the original
value. Language tags, when present, use BCP 47 syntax.

Role tokens MUST occur in the vocabulary named by `role_vocabulary`. Unknown
tokens fail validation; future additions use a new vocabulary identifier so
existing signed meanings do not drift.

Release dates allow year, year-month, or full-date precision. Calendar
validity must be checked beyond the schema regex. Track and disc numbers are
positive integers; totals, when supplied, cannot be smaller than their number.

## Compatibility

Version dispatch happens before typed validation. A v0.1 object continues to
use the unchanged v0.1 schema and signature domain. A v0.2 object uses only the
v0.2 schema and signing rules. A v0.1 manifest may be migrated only by issuing
a new v0.2 manifest with a new manifest ID and signature; its original bytes
remain a valid historical object.

## Security and privacy consequences

- Display names and credits are authenticated statements by the manifest
  issuer, not verified legal facts.
- Free-text fields can contain confusables or abusive content. Players should
  escape UI output and may display identity verification state separately.
- Identity references create correlation and privacy risks; they are optional
  on individual credits.
- Fixed length limits reduce memory and display-denial attacks.

## Alternatives rejected

- Adding optional fields to v0.1: incompatible with its closed schema and
  signed contract.
- A single `artist` string: loses ordering, identity links, and contributor
  semantics.
- Requiring a centrally registered contributor-role vocabulary: conflicts
  with the service-independent protocol goal.

## Review record

Resolved by the frozen schemas, contributor-role vocabulary, and ADR-011:
metadata is required; declared string limits are normative; applicable
non-NFC strings are rejected; the v0.2 role vocabulary is closed; and v0.2
has one canonical metadata presentation.

