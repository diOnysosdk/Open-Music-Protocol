#!/usr/bin/env python3
"""Run native Pi 400 validation and always emit JSON and Markdown evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import time

TIMEOUT_SECONDS = 45 * 60
REQUIRED_TOOLS = ("git", "cargo", "rustc", "python3", "pkg-config", "timeout")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def capture(command: list[str]) -> str:
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
        return (result.stdout or result.stderr).strip() or "unavailable"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").replace("\x00", "").strip()
    except OSError:
        return "unavailable"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    requested = Path(args.output)
    output = requested.resolve() if requested.is_absolute() else (root / requested).resolve()
    output.mkdir(parents=True, exist_ok=True)
    logs = output / "logs"
    logs.mkdir(exist_ok=True)

    started = utc_now()
    commit = capture(["git", "rev-parse", "HEAD"])
    arch = platform.machine().lower()
    bits = platform.architecture()[0]
    model = read_text("/proc/device-tree/model")
    system = {
        "hardware_model": model,
        "architecture": arch,
        "userspace_bits": bits,
        "operating_system": read_text("/etc/os-release"),
        "kernel": platform.release(),
        "platform": platform.platform(),
        "cpu_details": read_text("/proc/cpuinfo"),
        "rustc": capture(["rustc", "-Vv"]),
        "cargo": capture(["cargo", "-V"]),
        "memory": capture(["free", "-h"]),
        "filesystem": capture(["df", "-h", str(root)]),
        "audio_devices": capture(["aplay", "-l"]),
    }
    checks: list[dict[str, object]] = []

    def static_check(identifier: str, required: bool, passed: bool, diagnostic: str,
                     outcome: str | None = None) -> None:
        checks.append({"id": identifier, "required": required,
                       "outcome": outcome or ("PASS" if passed else ("FAIL" if required else "SKIP")),
                       "exit_code": 0 if passed else None, "duration_seconds": 0.0,
                       "diagnostic": diagnostic, "log": None})

    is_arm64 = arch in {"aarch64", "arm64"} and bits == "64bit"
    is_pi400 = "raspberry pi 400" in model.lower()
    static_check("native-arm64", True, is_arm64, f"architecture={arch}, userspace={bits}")
    static_check("raspberry-pi-400", True, is_pi400, f"hardware_model={model}")
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    alsa = capture(["pkg-config", "--modversion", "alsa"]) if not missing else "unavailable"
    sndfile = capture(["pkg-config", "--modversion", "sndfile"]) if not missing else "unavailable"
    time_tool = Path("/usr/bin/time").is_file()
    deps_ok = not missing and time_tool and alsa != "unavailable" and sndfile != "unavailable"
    static_check("build-dependencies", True, deps_ok,
                 f"missing_tools={missing}; /usr/bin/time={time_tool}; alsa={alsa}; sndfile={sndfile}")

    def run(identifier: str, command: list[str], required: bool = True) -> None:
        log_path = logs / f"{identifier}.log"
        began = time.monotonic()
        exit_code: int | None
        diagnostic = "completed"
        try:
            with log_path.open("w", encoding="utf-8") as stream:
                stream.write(f"command={shlex.join(command)}\nstarted_utc={utc_now()}\n")
                stream.flush()
                wrapped = ["/usr/bin/time", "-v", "timeout", f"{TIMEOUT_SECONDS}s", *command]
                result = subprocess.run(wrapped, cwd=root, stdout=stream,
                                        stderr=subprocess.STDOUT, check=False)
                exit_code = result.returncode
                stream.write(f"\ncompleted_utc={utc_now()}\nexit_code={exit_code}\n")
        except OSError as error:
            exit_code = None
            diagnostic = f"could not execute: {error}"
            log_path.write_text(diagnostic + "\n", encoding="utf-8")
        checks.append({"id": identifier, "required": required,
                       "outcome": "PASS" if exit_code == 0 else ("FAIL" if required else "SKIP"),
                       "exit_code": exit_code,
                       "duration_seconds": round(time.monotonic() - began, 3),
                       "diagnostic": diagnostic, "command": command,
                       "log": str(log_path.relative_to(output))})

    prerequisites = is_arm64 and is_pi400 and deps_ok
    commands = [
        ("workspace-build", ["cargo", "build", "--locked", "--workspace"]),
        ("workspace-tests", ["cargo", "test", "--locked", "--workspace"]),
        ("python-spec-tests", [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "omp-spec-v0.1/tests", "omp-spec-v0.2-draft/tests", "omp-spec-v0.2-amendments/tests"]),
        ("conformance", [sys.executable, "scripts/conformance.py", "--quiet", "--json", str(output / "conformance.json"), "--text", str(output / "conformance.txt")]),
        ("tooling-tests", [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-v"]),
        ("frozen-baseline", [sys.executable, "scripts/verify-frozen.py"]),
        ("cli-runtime-smoke", ["cargo", "run", "--locked", "-p", "omp-cli", "--", "--version"]),
        ("media-integration", ["cargo", "test", "--locked", "-p", "omp-media", "--test", "media_binding"]),
        ("playback-integration", ["cargo", "test", "--locked", "-p", "omp-player", "--test", "offline_playback"]),
    ]
    if prerequisites:
        for identifier, command in commands:
            run(identifier, command)
        display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        if display:
            run("desktop-runtime-smoke", ["timeout", "10s", "cargo", "run", "--locked", "-p", "omp-desktop"], required=False)
        else:
            static_check("desktop-runtime-smoke", False, False,
                         "no DISPLAY or WAYLAND_DISPLAY; desktop compilation is covered by workspace-build")
    else:
        for identifier, _ in commands:
            static_check(identifier, True, False,
                         "not executed because native Pi 400 prerequisites failed", "SKIP")
        static_check("desktop-runtime-smoke", False, False,
                     "not executed because native Pi 400 prerequisites failed")

    required_failures = [str(c["id"]) for c in checks if c["required"] and c["outcome"] != "PASS"]
    verdict = "PASS" if not required_failures else ("BLOCKED" if not prerequisites else "FAIL")
    completed = utc_now()
    git_status = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                                text=True, capture_output=True, check=False)
    evidence = {
        "schema": "omp-w8-11-hardware-evidence-v1", "started_utc": started,
        "completed_utc": completed, "git_commit": commit,
        "repository_clean": git_status.returncode == 0 and not git_status.stdout.strip(),
        "physical_hardware_attestation": "system-reported model and native architecture; retain operator SSH/asset provenance",
        "system": system, "checks": checks, "required_failures": required_failures,
        "hardware_validation_verdict": verdict,
        "w8_11_security_finding": "OPEN/HIGH; hardware validation does not remediate the FLAC allocation finding",
    }
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = "\n".join(f"| `{c['id']}` | {str(c['required']).lower()} | {c['outcome']} | {c['exit_code']} | {c['diagnostic']} |" for c in checks)
    report = f"""# OMP Raspberry Pi 400 ARM64 validation\n\n- Started: `{started}`\n- Completed: `{completed}`\n- Commit: `{commit}`\n- Hardware: `{model}`\n- Architecture: `{arch}` / `{bits}`\n- Hardware validation verdict: **{verdict}**\n- W8-11 security finding: **OPEN/HIGH**\n\n| Check | Required | Outcome | Exit | Diagnostic |\n|---|---:|---|---:|---|\n{rows}\n\nHardware qualification cannot close the separately defined W8-11 FLAC memory-exhaustion finding.\n"""
    (output / "report.md").write_text(report, encoding="utf-8")
    print(f"hardware validation verdict: {verdict}")
    return 0 if verdict == "PASS" else (2 if verdict == "BLOCKED" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
