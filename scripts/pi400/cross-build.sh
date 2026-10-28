#!/usr/bin/env sh
set -eu

target=aarch64-unknown-linux-gnu
command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || {
  echo "BLOCKED: install an aarch64-linux-gnu cross linker explicitly" >&2
  exit 2
}
rustup target list --installed | grep -qx "$target" || {
  echo "BLOCKED: run 'rustup target add $target' after reviewing the toolchain download" >&2
  exit 2
}
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
cargo build --release --locked --target "$target" -p omp-cli -p omp-player -p omp-desktop
echo "Experimental cross-build complete. Runtime compatibility is NOT established until tested on ARM64 hardware."
