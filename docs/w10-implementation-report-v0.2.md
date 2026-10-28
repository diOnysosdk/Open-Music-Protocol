# W10 desktop reference player and Raspberry Pi 400 report

Date: 2026-10-27. Final commit and hosted run identifiers are reported in the
Git history and W10 handoff because a commit cannot contain its own SHA.

## Architecture and interface

ADR-015 selects Rust-native `eframe/egui` 0.33 with the `glow` backend. The
`omp-desktop` crate separates `library` persistence, testable `state`, OMP
`service`, and `ui`. No network client or server exists. The desktop layout is
built from a locked dependency graph requiring Rust 1.88 or newer. It is
dark, high-contrast, resizable, and keyboard navigable: left Library/Albums/
Artists/Queue navigation, central searchable collection/import, right security
details, and bottom transport.

The library imports directories containing `manifest.json`, `license.json`,
and `identity.json`. It indexes title, ordered artist credits, release/album,
canonical path, integrity facts, and six separate security axes only after
cryptographic authentication. Missing directories are marked without
reinterpreting their old contents. OMP v0.2 has no authenticated duration or
artwork field, so the UI honestly reports duration as undeclared and does not
load unverified artwork.

Import and playback require an explicit local assertion that signer identity
trust was established through an independent channel. It defaults off and is
not persisted. Self-signature or package possession never upgrades trust.

Play calls the full `omp_player::prepare` pipeline and can create a
`LocalPlayback` only from its opaque `PreparedPlayback`. Pause/resume, stop,
seek, progress, volume, previous/next, queue, completion, and keyboard commands
operate on that authorized session. Headless state and existing playback tests
require no speakers. Signature validity is explicitly not presented as
ownership, authorization, entitlement, or legal rights.

## Phase record

| Phase | Status | Evidence and remaining work |
|---|---|---|
| 0 Repository assessment | PASS | Required baseline clean; 55 Rust tests and 42/42 frozen verification passed |
| 1 GUI architecture | PASS | ADR-015; workspace build and Windows launch smoke test |
| 2 Music library | PASS | Verified-only persistence, import, search, groups, missing/invalid handling; v0.2 has no artwork/duration fields |
| 3 Playback | PASS | Opaque prepared-handle boundary plus controllable Rodio session; no decoder changes |
| 4 Trust/licensing UI | PASS | Six backend-derived axes and stable diagnostic explanations |
| 5 Reference design | PASS | Dark responsive four-region interface, loading/empty/error states and shortcuts |
| 6 Pi environment | PASS (prepared) | Idempotent reviewed setup and architecture preflight; no OS changes executed |
| 7 SSH workflow | PASS (prepared) | Manual key-only OpenSSH entry point; no credentials or network changes |
| 8 Native Pi tests | BLOCKED | No explicitly configured/authorized physical Pi connection was available |
| 9 ARM cross-build | BLOCKED locally | Reproducible script prepared; Windows host lacks reviewed GNU ARM linker/sysroot and no target runtime was available |
| 10 Regression | PASS | Workspace, conformance, GUI/state, packaging, docs, formatting, Clippy, frozen baseline and secret checks |
| 11 Packaging | PASS where executed | Internal Windows package verified locally; hosted Linux desktop package required for Linux PASS |
| 12 Git/hosted CI | Recorded in handoff | Exact-commit Windows/Linux/audit/package jobs required before final PASS |

## Packaging and ARM boundaries

Desktop packages contain three binaries, locked dependency metadata, license
and security documents, a generated CycloneDX inventory, and complete
`SHA256SUMS`. The audit enforces the exact inventory and rejects private-looking
JSON fields. No package is a release. ARM64 packages remain experimental until
the native process in `pi400-validation.md` produces actual device evidence.

## Limitations, verdicts, and W11 recommendation

`W8-11` remains **OPEN/HIGH**. External alpha and production remain **NO-GO**.
The GUI currently supports one active local audio session, package-directory
import rather than archive extraction, and no artwork/duration because the
frozen protocol does not authenticate those fields. Trusted-time-limited and
subject licenses fail closed without a configured secure platform adapter.

Recommended W11: remediate and independently review `W8-11`; add certified
rollback-resistant Windows/Linux trust/time stores; collect real Pi 400 ARM64
evidence; perform accessibility review and hardware audio/device-loss testing;
then complete independently signed reproducible desktop packages.
