#!/usr/bin/env bash
set -euo pipefail

output="${1:-dist/omp-v0.2-alpha-linux-x86_64}"
if [[ -e "$output" ]]; then
  echo "error: output already exists; choose a new empty candidate path: $output" >&2
  exit 2
fi

python3 scripts/verify-frozen.py
cargo build --release --locked -p omp-cli -p omp-player
mkdir -p "$output/sbom" "$output/samples"
cp target/release/omp target/release/omp-player "$output/"
cp README.md LICENSE-MIT LICENSE-APACHE THIRD-PARTY-NOTICES.md "$output/"
cp scripts/verify-alpha.py scripts/audit-alpha.py "$output/"
cp docs/SECURITY.md docs/alpha-installation-v0.2.md \
  docs/alpha-package-workflow-v0.2.md docs/w8-alpha-readiness-v0.2.md \
  docs/w8-release-readiness-v0.2.md docs/w8-alpha-candidate-report-v0.2.md \
  "$output/"
find crates -name '*.cdx.json' -type f -exec cp {} "$output/sbom/" \;
cp omp-spec-v0.2-draft/fixtures/audio/* "$output/samples/"
cp omp-spec-v0.2-draft/fixtures/LICENSE.md "$output/samples/LICENSE.md"
cat >"$output/EXPERIMENTAL-ALPHA.txt" <<'EOF'
OMP v0.2 - Experimental Alpha / Not Production Ready

This internal, unsigned candidate is not approved for publication or production use.
Verify SHA256SUMS through an independently authenticated channel before execution.
See w8-alpha-candidate-report-v0.2.md for limitations and security requirements.
EOF
(
  cd "$output"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | \
    xargs -0 sha256sum | sed 's#  \./#  #'>SHA256SUMS
)
python3 scripts/verify-alpha.py "$output"
python3 scripts/audit-alpha.py "$output" linux
