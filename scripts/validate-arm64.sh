#!/usr/bin/env sh
set -eu

case "$(uname -m)" in
  aarch64|arm64) ;;
  *) echo "SKIP: ARM64 validation must run on actual ARM64 hardware (found $(uname -m))" >&2; exit 2 ;;
esac

echo "EXPERIMENTAL: this validates the current host; it does not certify ARM64 compatibility"
cargo test --locked --workspace
python3 scripts/conformance.py --quiet
python3 scripts/verify-frozen.py
