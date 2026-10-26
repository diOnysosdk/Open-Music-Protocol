# OMP v0.2 W8 threat model

## Assets and boundaries

Protected assets are signing keys, authenticated protocol bytes, accepted
identity branches, durable pins, trusted-time high-water state, verified media
handles, and playback permits. Attackers may control JSON, package paths,
filesystem contents, delivery order, clocks, malformed audio, stale backups,
and unavailable devices. A fully compromised OS/device and dishonest legal
claims remain outside enforceable guarantees.

## Principal threats and controls

- Signature confusion: exact typed domains, RFC 8785 bytes, no fallback.
- Backdating/revoked keys: ADR-013 order/evidence rules; claimed timestamps do
  not establish authorization.
- Fork/rollback: retain conflicts, monotonic sequences/high-water marks, fail
  closed unless the exact approved public-pin exception applies.
- Pin forgery: exact hashes/sizes/tips/roles, non-TOFU origin, opaque result,
  mandatory rollback-capable platform store.
- Clock rollback: signed authorized anchor, monotonic elapsed time,
  uncertainty interval, maximum age, durable checkpoint.
- Path escape/TOCTOU: strict portable paths, descriptor/reparse traversal,
  private verified snapshot passed directly to decoder.
- Decoder exhaustion: media magic, signed size ceiling, packet/frame limits,
  streaming output duration cap. Fuzz/isolation review remains required.
- Supply chain: locked dependencies, RustSec CI, read-only workflow
  permissions, SBOM/license work before release.
- Privacy: offline operation and no telemetry; local identity/pin data still
  requires access control and retention policy.

Residual risk includes withheld offline revocations, compromised endpoints,
platform secure-storage weaknesses, audio-driver defects, dependency
vulnerabilities, and denial of service. OMP is not DRM and does not prove
legal ownership.

