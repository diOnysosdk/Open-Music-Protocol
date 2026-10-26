# W8 supply-chain, license, SBOM and privacy assessment

The workspace lockfile is authoritative and CI runs RustSec. `cargo audit
--json` on 2026-10-26 examined 186 locked packages against a 1,378-advisory
database and reported zero vulnerabilities or warnings. Rodio,
CPAL, Symphonia, Ed25519-dalek, serde, time, tempfile, rustix and their
transitives are the principal review surface.

No production Rust source contains an explicit `unsafe` block. Test-only
private seeds occur only in frozen vectors, tests, and the deterministic vector
generator. No network client or telemetry crate is present.

Final SPDX/CycloneDX SBOM and third-party notices must be generated from the
locked release build and independently checked; they were not fabricated in
this audit. Required pre-release tools include `cargo audit`, `cargo deny` or
equivalent license policy, CycloneDX/SPDX generation, and a repository secret
scanner. Local identity, subject, pin and listening-state data is personal or
correlatable data and needs least-privilege storage, deletion/export policy,
and no telemetry by default.

