#!/usr/bin/env bash
set -euo pipefail
output="${1:-dist/omp-v0.2-desktop-linux-x86_64}"
[[ ! -e "$output" ]] || { echo "output already exists: $output" >&2; exit 2; }
python3 scripts/verify-frozen.py
cargo build --release --locked -p omp-desktop -p omp-cli -p omp-player
mkdir -p "$output/sbom"
cp target/release/omp-desktop target/release/omp target/release/omp-player "$output/"
cp README.md Cargo.lock LICENSE-MIT LICENSE-APACHE THIRD-PARTY-NOTICES.md "$output/"
cp docs/SECURITY.md docs/developer-quickstart-v0.2.md docs/reference-apis-v0.2.md docs/w10-implementation-report-v0.2.md "$output/"
cp scripts/verify-alpha.py scripts/audit-desktop.py "$output/"
python3 scripts/generate-desktop-sbom.py "$output/sbom/omp-desktop.cdx.json"
printf '%s\n' 'OMP v0.2 Desktop Reference Player - Internal / Not Production Ready' 'W8-11 remains OPEN/HIGH. External alpha and production release are NO-GO.' >"$output/EXPERIMENTAL-DESKTOP.txt"
(cd "$output" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum | sed 's#  \./#  #'>SHA256SUMS)
python3 scripts/verify-alpha.py "$output"
python3 scripts/audit-desktop.py "$output" linux
