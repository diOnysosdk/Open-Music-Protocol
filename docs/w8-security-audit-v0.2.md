# OMP v0.2 W8 security audit

Date: 2026-10-26. Scope: repository implementation, not an independent
third-party audit. Frozen baseline: `OMP-v0.2-w0-freeze.1`.

## Traceability and findings

| Security requirement | Implementation | Evidence | Status |
|---|---|---|---|
| Exact versions, closed schemas, duplicate JSON keys | `omp-core::v02` | core/schema Python negatives | Pass |
| RFC 8785, six domains, Ed25519 | `omp-crypto::V02Profile` | published vectors/domain swaps | Pass |
| Identity, threshold, lifecycle, forks | `omp-identity` | chain/fork/rollback suites | Pass |
| Historical authorization and pin exception | opaque W4 facts and `assess_durable_pin` | semantic and W4-W7 tests | Pass with platform-store dependency |
| Trust bundles and TOFU | production fact provider/merge | role, order, TOFU negatives | Pass |
| Licensing and trusted time | `omp-license` | boundary/rollback tests | Pass with platform-clock/store dependency |
| Paths, hashes, TOCTOU | `omp-media` openat/reparse guards/private snapshot | Windows path/race suite | Linux execution pending |
| Non-forgeable player decisions | opaque W4 result/W6 permit/W7 prepared playback | compile-time boundaries and negatives | Pass |
| Decoder/output resource limits | Symphonia limits; Rodio four-hour cap | headless/mocked sink tests | Device and fuzz assurance pending |

## Finding register

| ID | Severity | Finding | Status/owner |
|---|---|---|---|
| W8-01 | High | No certified rollback-resistant pin/time-store adapter exists. Restricted operations must fail closed. | Open, platform security |
| W8-02 | High | No independent cryptographic/filesystem review has occurred. | Open, protocol owner |
| W8-03 | Medium | Linux openat and audio paths have not executed locally. | CI added; release engineering |
| W8-04 | Medium | Real-device loss/interruption and malformed decoder campaigns are incomplete. | Open, audio security |
| W8-05 | Medium | Long-running fuzz campaigns have not run; only targets/corpus are supplied. | Open, QA |
| W8-06 | Medium | Rodio playback caps duration but uses its streaming decoder path rather than W7's packet counter. | Open, audio security |
| W8-07 | Low | Deterministic test private seeds are present in fixtures/tests and one generator example. No production module imports them. | Accepted test-only; release scan required |
| W8-08 | Low | Local pins/identities can be sensitive correlation data. | Privacy documentation and platform encryption/access control required |
| W8-09 | Medium | GitHub-hosted Windows/Linux CI has not executed for the candidate revision because no authenticated GitHub session was available. | Open, repository owner/release engineering |
| W8-10 | Medium | Windows sanitizer fuzzing could not link without the LLVM ASan runtime; no bounded campaign statistics exist. | Open, CI/QA; run on supported Linux nightly runner |

Supply-chain evidence generated locally: CycloneDX 1.5 SBOMs for all eight
crates, zero RustSec findings across 186 locked packages, a 186-package license
inventory, and a Gitleaks history scan with no findings. These outputs must be
regenerated and archived by hosted CI for the exact candidate commit.

No production crate contains explicit `unsafe` blocks. No network client or
telemetry dependency is used by the protocol/player code. Cryptographic
authenticity continues to be distinct from authorization and legal ownership.

