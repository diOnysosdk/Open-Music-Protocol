# Raspberry Pi 400 validation

Status: **PREPARED; NATIVE EXECUTION BLOCKED pending explicitly configured
hardware access.** No hostname, address, username, password, or private key is
stored in this repository. The runner requires both a 64-bit ARM userspace and
a system-reported `Raspberry Pi 400` model; another ARM64 host cannot produce a
PASS for this hardware gate.

## Inspect before changing anything

On the Pi, record `uname -m`, `getconf LONG_BIT`, `/etc/os-release`, `free -h`,
`df -h`, `rustc --version`, `cargo --version`, `pkg-config --modversion alsa`,
and `aplay -l`. An `aarch64` kernel is insufficient if `getconf LONG_BIT`
reports 32. A 32-bit userspace cannot run standard aarch64 binaries; either
test natively as 32-bit without making ARM64 claims, or have the owner manually
choose and install a supported 64-bit Raspberry Pi OS. Scripts never reimage or
upgrade the OS.

After reviewing package changes, run `sh scripts/pi400/setup.sh`. It installs
build/audio/window dependencies idempotently but deliberately refuses to
bootstrap Rust from an unauthenticated pipe. It creates an isolated validation
Python environment under `$HOME/.venv-omp-validation`. Then run
`sh scripts/pi400/validate.sh`. The runner uses 45-minute command limits,
captures `/usr/bin/time -v` resource measurements, and archives architecture,
OS, Rust, exact commit, every exit code, conformance JSON/text, per-step logs,
`evidence.json`, and `report.md` under `validation/evidence/w8-11`.

A PASS means the mandatory development, integration, runtime, conformance, and
frozen-baseline checks ran natively on a system reporting Raspberry Pi 400 and
ARM64. A missing display is recorded as a desktop runtime SKIP; the desktop
binary must still compile. Unsupported hardware, missing prerequisites, and
unexecuted required checks can never produce PASS.

Do not reproduce `W8-11`, run unrestricted fuzzing, expose test services, or
install a self-hosted CI runner on the network-connected Pi.

## Optional Windows-to-Pi execution

Configure SSH public-key authentication and verify the host key out of band.
Prefer a dedicated unprivileged account and segmented network; otherwise limit
SSH at the Pi firewall to the trusted LAN. No OMP service needs a listening
socket. From PowerShell, after the owner supplies real values:

```powershell
./scripts/pi400/run-remote-tests.ps1 -HostName '<pi-host>' -UserName '<test-user>' -IdentityFile '<key-path>'
```

Add `-ApproveSetup` only after reviewing and approving the one-time `apt`
changes. Routine validation uses no privileged remote command. The workflow
checks out the exact local commit in detached mode and copies logs back to
`validation/evidence/w8-11/collected/<commit>` even when validation fails; it
transfers no production secrets. Use `-Port` for a non-default SSH port.

Hardware qualification is distinct from the existing `W8-11` security
finding. `W8-11` is the High-severity FLAC allocation failure documented in
the W8 security audit. Pi execution can add device evidence but cannot close
that finding without its required remediation, regression, and clean repeat
of all five ASan campaigns.

## Cross-compilation

`scripts/pi400/cross-build.sh` targets `aarch64-unknown-linux-gnu` and fails
clearly unless both the Rust target and GNU cross-linker are already installed.
ALSA and GUI libraries for the target architecture must also be available to
the linker. Cross-compilation is preparation only: binaries remain
**experimental/unvalidated** until executed through the native procedure on a
compatible 64-bit Pi.
