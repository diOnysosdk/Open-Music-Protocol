"""Verify the frozen W0 manifest across checkout line-ending policies."""

from __future__ import annotations

import hashlib
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "omp-spec-v0.2-draft" / "SHA256SUMS"
MANIFEST_SHA256 = "fc912bbcfab93b72f958347a3fabc0fef6e781977b2b705c4958687d72e12218"
ENTRY = re.compile(r"^([0-9a-f]{64})\s+\*?(.+)$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recorded_bytes(data: bytes) -> bytes | None:
    """Return W0's CRLF representation for normalized UTF-8 checkout text."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")


def main() -> int:
    manifest_data = MANIFEST.read_bytes()
    manifest_recorded = recorded_bytes(manifest_data)
    if sha256(manifest_data) != MANIFEST_SHA256 and (
        manifest_recorded is None or sha256(manifest_recorded) != MANIFEST_SHA256
    ):
        print("frozen checksum manifest changed", file=sys.stderr)
        return 1

    failures: list[str] = []
    entries = 0
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        match = ENTRY.fullmatch(line)
        if not match:
            continue
        entries += 1
        expected, relative = match.groups()
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"missing: {relative}")
            continue
        data = path.read_bytes()
        if sha256(data) == expected:
            continue
        normalized = recorded_bytes(data)
        if normalized is None or sha256(normalized) != expected:
            failures.append(f"hash mismatch: {relative}")

    if entries != 41:
        failures.append(f"expected 41 entries, found {entries}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("42/42 frozen artifacts verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
