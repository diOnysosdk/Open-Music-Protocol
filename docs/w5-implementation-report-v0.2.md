# OMP v0.2 W5 metadata and deterministic media-binding report

Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1` plus ADR-013 and ADR-014  
Recommendation: **CONDITIONAL GO for controlled integration; NO-GO for production release**.

## Implementation

The new `omp-media` crate owns W5 filesystem and media behavior. It reuses
`omp-core::v02` for exact version dispatch, closed models, metadata validation,
and portable paths, and reuses the typed `omp-crypto::V02Profile::Manifest`
verification API. It contains no alternative canonicalizer or signature
profile.

Public boundaries:

- `AuthenticatedManifest::parse_and_verify` returns an opaque W2/W3-valid
  manifest. It proves cryptographic authenticity, not W4 authorization, legal
  ownership, or playback entitlement.
- `PackageRoot::open` requires an explicit local directory.
- `select_and_verify` sorts supported non-preview assets by unique signed rank,
  binds the first successfully verified candidate, and never uses array or
  directory order.
- `VerifiedMedia` owns a private verified snapshot handle, rewound for transfer
  to a future decoder through `into_file`; no untrusted pathname is reopened.
- `MediaPolicy` imposes a caller-selected resource ceiling separately from
  protocol validity.

W2 metadata validation now also checks calendar-valid partial release dates,
BCP 47 extension structure within the frozen schema's lexical envelope, and
the normative 1024-byte UTF-8 portable-path limit. Signed strings are rejected,
never normalized or rewritten. NFC confusables remain distinct authenticated
text because v0.2 defines no confusable-equivalence policy.

## Filesystem security

Windows opens and retains every directory component without delete sharing,
uses `FILE_FLAG_OPEN_REPARSE_POINT`, rejects reparse attributes, and excludes
write/delete sharing on the source asset during snapshot verification. Unix
uses descriptor-relative `openat` for every component with `O_NOFOLLOW`.

The source is streamed once into an OS-managed private temporary handle while
checking the signed size and SHA-256. The decoder receives that exact verified
snapshot. Later pathname replacement or in-place package-file mutation cannot
change the verified decoder input.

Only RIFF/WAVE and native FLAC magic are supported in W5. MPEG, Ogg, and MP4
remain schema-valid but return unsupported/unavailable until separately
reviewed decoder profiles exist. Extensions are never authoritative.

## Acceptance matrix

| Criterion | Result |
|---|---|
| Frozen artifacts unchanged | Pass |
| NFC metadata rejected without rewriting | Pass |
| Contributor roles and release metadata | Pass through W2 |
| Calendar-valid release dates and BCP 47 extensions | Pass |
| Portable relative paths and UTF-8 byte limit | Pass |
| Absolute, traversal, backslash, percent and colon forms | Pass |
| Reserved Windows device segments | Pass |
| Case-fold collision detection | Pass |
| Unique IDs, paths, ranks and one primary | Pass through W2 |
| WAV/FLAC magic, size and SHA-256 binding | Pass |
| Deterministic selection independent of array order | Pass |
| Same verified handle reaches decoder boundary | Pass via private snapshot |
| Symlink/reparse rejection | Pass on available Windows test |
| Path replacement after verification | Pass |
| No network or private-key package behavior | Pass |
| Linux filesystem execution | Not run in this Windows environment |
| Junction-specific and hostile concurrent stress assurance | External review required |

## W6/W7 integration

W6 must remain a separate entitlement decision and must not infer permission
from `AuthenticatedManifest` or `VerifiedMedia`. W7 must require the relevant
W4 authorization result and W6 license decision before transferring
`VerifiedMedia::into_file` to a decoder. It must not reopen `relative_path`.

## Remaining blockers

- Run the Unix `openat` suite in Linux CI and junction/race stress tests in a
  privileged Windows CI worker.
- Independent review of Windows share-mode/reparse handling and Unix
  descriptor-relative traversal.
- Fuzz the duplicate-safe JSON boundary, BCP 47 validator, portable paths, and
  media header sniffers.
- Review temporary-file placement, encryption-at-rest expectations, and local
  disk-exhaustion policy per deployment.

