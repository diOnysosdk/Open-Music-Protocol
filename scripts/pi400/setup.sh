#!/usr/bin/env sh
set -eu

echo "OMP Raspberry Pi 400 setup (safe to rerun; does not change the OS release)"
uname -m
getconf LONG_BIT
cat /etc/os-release
free -h
df -h .

if [ "$(getconf LONG_BIT)" != "64" ]; then
  echo "STOP: 32-bit userspace cannot run aarch64-unknown-linux-gnu binaries." >&2
  echo "Choose native 32-bit development or manually install a supported 64-bit OS; this script will not reimage the device." >&2
  exit 2
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required for the explicitly approved one-time dependency installation" >&2
  exit 2
fi

sudo apt-get update
sudo apt-get install -y --no-install-recommends build-essential pkg-config libasound2-dev libsndfile1 libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev python3 python3-venv git time

if ! command -v rustup >/dev/null 2>&1; then
  echo "Rust is absent. Install rustup manually from an authenticated source, then rerun." >&2
  exit 2
fi
rustup toolchain install stable --component rustfmt,clippy
rustc --version
cargo --version
echo "Setup complete; no service, firewall, runner, or network configuration was changed."
