#!/usr/bin/env python3
"""Audit the exact internal desktop package inventory and secret boundary."""

import json
import pathlib
import sys

COMMON = {
    "Cargo.lock", "EXPERIMENTAL-DESKTOP.txt", "LICENSE-APACHE", "LICENSE-MIT",
    "README.md", "SECURITY.md", "SHA256SUMS", "THIRD-PARTY-NOTICES.md",
    "audit-desktop.py", "developer-quickstart-v0.2.md", "reference-apis-v0.2.md",
    "verify-alpha.py", "w10-implementation-report-v0.2.md", "sbom/omp-desktop.cdx.json",
}


def private(value: object) -> bool:
    if isinstance(value, dict):
        return any("private" in str(key).casefold() or private(item) for key, item in value.items())
    if isinstance(value, list):
        return any(private(item) for item in value)
    return False


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in {"windows", "linux"}:
        print("usage: audit-desktop.py DIST_DIR <windows|linux>", file=sys.stderr); return 2
    root = pathlib.Path(sys.argv[1]).resolve()
    suffix = ".exe" if sys.argv[2] == "windows" else ""
    expected = COMMON | {f"omp{suffix}", f"omp-player{suffix}", f"omp-desktop{suffix}"}
    actual = {item.relative_to(root).as_posix() for item in root.rglob("*") if item.is_file()}
    if actual != expected:
        print(f"inventory mismatch: missing={sorted(expected-actual)} unexpected={sorted(actual-expected)}", file=sys.stderr); return 1
    sbom = json.loads((root / "sbom/omp-desktop.cdx.json").read_text(encoding="utf-8"))
    if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("components"):
        print("invalid or empty desktop SBOM", file=sys.stderr); return 1
    for relative in actual:
        if ".private." in relative.casefold():
            print(f"private-looking file: {relative}", file=sys.stderr); return 1
        if relative.endswith(".json") and private(json.loads((root / relative).read_text(encoding="utf-8"))):
            print(f"private field in {relative}", file=sys.stderr); return 1
    print(f"audited desktop package: {len(actual)} files, {len(sbom['components'])} SBOM components, no private material")
    return 0


if __name__ == "__main__": raise SystemExit(main())
