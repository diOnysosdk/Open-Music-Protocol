# OMP v0.2 W8 release readiness

## Readiness decision

- Controlled development: **GO**.
- W8.5 packaging qualification: **PASS** on hosted Windows, Ubuntu, RustSec,
  and Linux packaging run `40500074568` for commit `9b88fb48`.
- External alpha/release-candidate testing: **NO-GO** while `W8-11` remains
  OPEN/HIGH; a clean five-target sanitizer rerun is required after remediation.
- Production release: **NO-GO** pending independent review, production secure
  storage/time adapters, fuzz campaigns, reproducibility, signed artifacts,
  and explicit protocol-owner approval.

## Reproducible gates

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
python -m pytest -p no:cacheprovider omp-spec-v0.1/tests omp-spec-v0.2-draft/tests omp-spec-v0.2-amendments/tests
cargo install cargo-fuzz
cargo fuzz run json_v02 -- -max_total_time=60
cargo fuzz run canonicalization -- -max_total_time=60
cargo audit
```

The frozen `SHA256SUMS` entries and its recorded manifest hash must be checked
before and after every release build. Build with `--locked`. Release archives
must include source revision, compiler/target, lockfile, checksums, SBOM,
licenses, and detached signatures from an offline release key. Two-person
verification is required; no signing was performed in W8.

## Compatibility matrix

| Target | Build/test status | Remaining |
|---|---|---|
| Windows x86_64 MSVC | Local tests and two-build reproducibility pass | hosted CI, hardware audio, privileged junction, secure-store adapter |
| Linux x86_64 GNU | CI configured | first successful run, ALSA/device tests, openat stress |
| v0.1 | regression suite passes | preserve indefinitely |
| v0.2 | controlled implementation passes local gates | external interop/security review |

## W0-W8 acceptance summary

| Workstream | Status |
|---|---|
| W0 specification freeze | Pass; 42-artifact baseline unchanged |
| W1 conformance fixtures | Pass locally; cross-platform CI pending |
| W2 versioned models | Pass |
| W3 cryptographic profiles | Pass vectors; independent review pending |
| W4 identity/offline trust | Controlled GO; production stores pending |
| W5 metadata/media binding | Controlled GO; Linux/privileged Windows assurance pending |
| W6 licensing/trusted time | Controlled GO; secure clock/store adapters pending |
| W7 offline player | Controlled GO; hardware matrix pending |
| W8 assurance/release | Local assurance only; external alpha and production blocked |

## Release checklist and remediation order

1. Obtain green Windows/Linux CI and archive logs.
2. Run RustSec, secret, license, and SBOM tooling; disposition every finding.
3. Implement/certify platform rollback-resistant pin/time stores.
4. Run fuzz campaigns and decoder corpora with sanitizer builds.
5. Complete hardware audio/device-loss and filesystem race matrices.
6. Commission independent cryptographic and application security review.
7. Produce reproducible artifacts twice on isolated builders and compare.
8. Generate SBOM, notices, checksums and detached signatures.
9. Protocol owner reviews evidence and explicitly approves release.

Security reports should be sent privately to the project security contact
published with the eventual repository. Until that contact exists, do not
publish production artifacts; this document is not a complete vulnerability
disclosure channel.

