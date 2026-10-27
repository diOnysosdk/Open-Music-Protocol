#!/usr/bin/env python3
"""Enforce the reviewed inventory and private-material boundary of a candidate."""

from __future__ import annotations

import json
import pathlib
import sys

CRATES = {
    "omp-cli",
    "omp-core",
    "omp-crypto",
    "omp-identity",
    "omp-license",
    "omp-manifest",
    "omp-media",
    "omp-player",
}
REQUIRED = {
    "README.md",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "THIRD-PARTY-NOTICES.md",
    "SECURITY.md",
    "alpha-installation-v0.2.md",
    "alpha-package-workflow-v0.2.md",
    "EXPERIMENTAL-ALPHA.txt",
    "SHA256SUMS",
    "verify-alpha.py",
    "audit-alpha.py",
    "w8-alpha-readiness-v0.2.md",
    "w8-release-readiness-v0.2.md",
    "w8-alpha-candidate-report-v0.2.md",
    "samples/LICENSE.md",
    "samples/fixture-index.json",
    "samples/omp-triangle-250ms.wav",
    "samples/omp-triangle-250ms.flac",
}


def contains_private_field(value: object) -> bool:
    if isinstance(value, dict):
        if any("private" in str(key).casefold() for key in value):
            return True
        return any(contains_private_field(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_private_field(item) for item in value)
    return False


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in {"windows", "linux"}:
        print("usage: audit-alpha.py DIST_DIR <windows|linux>", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1]).resolve()
    platform = sys.argv[2]
    if not root.is_dir():
        print("error: candidate directory does not exist", file=sys.stderr)
        return 2
    files = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    required = REQUIRED | ({"omp.exe", "omp-player.exe"} if platform == "windows" else {"omp", "omp-player"})
    missing = sorted(required - files)
    if missing:
        print(f"error: missing required files: {', '.join(missing)}", file=sys.stderr)
        return 1
    expected_sbom_files = {f"sbom/{crate}.cdx.json" for crate in CRATES}
    unexpected = sorted(files - required - expected_sbom_files)
    if unexpected:
        print(f"error: unexpected candidate files: {', '.join(unexpected)}", file=sys.stderr)
        return 1
    sboms = {pathlib.PurePosixPath(item).stem.removesuffix(".cdx") for item in files if item.startswith("sbom/") and item.endswith(".cdx.json")}
    if sboms != CRATES:
        print("error: candidate must contain exactly one SBOM for each workspace crate", file=sys.stderr)
        return 1
    for relative in files:
        lowered = pathlib.PurePosixPath(relative).name.casefold()
        if ".private." in lowered or lowered.startswith("private-"):
            print(f"error: private-looking file in candidate: {relative}", file=sys.stderr)
            return 1
        if relative.endswith(".json") and not relative.startswith("sbom/"):
            try:
                value = json.loads((root / pathlib.PurePosixPath(relative)).read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                print(f"error: invalid packaged JSON {relative}: {error}", file=sys.stderr)
                return 1
            if contains_private_field(value):
                print(f"error: private field in packaged JSON: {relative}", file=sys.stderr)
                return 1
    print(f"audited {len(files)} files; 8 SBOMs; no private key documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
