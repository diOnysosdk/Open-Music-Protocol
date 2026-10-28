#!/usr/bin/env sh
set -eu

case "$(uname -m):$(getconf LONG_BIT)" in
  aarch64:64|arm64:64) ;;
  *) echo "BLOCKED: native ARM64 validation requires a 64-bit ARM kernel and userspace" >&2; exit 2 ;;
esac

commit=$(git rev-parse HEAD)
output="${1:-target/pi400-validation}"
mkdir -p "$output"
log="$output/validation.log"
summary="$output/summary.txt"

{
  echo "OMP Raspberry Pi 400 validation"
  echo "commit=$commit"
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  uname -a
  getconf LONG_BIT
  cat /etc/os-release
  rustc -Vv
  cargo -V
  free -h
  df -h .
  if command -v aplay >/dev/null 2>&1; then aplay -l || true; else echo "aplay unavailable"; fi
} >"$summary" 2>&1

run() {
  echo "== $*" | tee -a "$log"
  /usr/bin/time -v timeout 45m "$@" >>"$log" 2>&1
}

run cargo test --locked --workspace
run python3 scripts/conformance.py --quiet --json "$output/conformance.json" --text "$output/conformance.txt"
run python3 scripts/verify-frozen.py
run cargo test --locked -p omp-cli --test cli_usability
run cargo test --locked -p omp-media --test media_binding
run cargo test --locked -p omp-license --test license_engine
run cargo test --locked -p omp-identity
run cargo test --locked -p omp-player --test offline_playback
run cargo build --locked -p omp-desktop

echo "completed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$summary"
echo "result=PASS" >>"$summary"
echo "Logs written to $output"
