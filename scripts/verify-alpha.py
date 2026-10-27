#!/usr/bin/env python3
"""Verify every entry in an OMP alpha candidate SHA256SUMS file."""

from __future__ import annotations

import hashlib
import pathlib
import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify-alpha.py DIST_DIR", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1]).resolve()
    sums = root / "SHA256SUMS"
    if not root.is_dir() or not sums.is_file():
        print("error: DIST_DIR must contain SHA256SUMS", file=sys.stderr)
        return 2
    seen: set[pathlib.Path] = set()
    for number, line in enumerate(sums.read_text(encoding="utf-8").splitlines(), 1):
        try:
            expected, relative_text = line.split("  ", 1)
        except ValueError:
            print(f"error: malformed SHA256SUMS line {number}", file=sys.stderr)
            return 1
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            print(f"error: invalid SHA-256 on line {number}", file=sys.stderr)
            return 1
        if "\\" in relative_text:
            print(f"error: non-portable checksum path on line {number}", file=sys.stderr)
            return 1
        relative = pathlib.PurePosixPath(relative_text)
        if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
            print(f"error: unsafe checksum path on line {number}", file=sys.stderr)
            return 1
        path = root.joinpath(*relative.parts).resolve()
        unresolved = root.joinpath(*relative.parts)
        if (
            root not in path.parents
            or path in seen
            or unresolved.is_symlink()
            or not path.is_file()
        ):
            print(f"error: missing, duplicate, or escaping file: {relative}", file=sys.stderr)
            return 1
        seen.add(path)
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        actual = digest.hexdigest()
        if actual != expected:
            print(f"error: checksum mismatch: {relative}", file=sys.stderr)
            return 1
    entries = list(root.rglob("*"))
    if any(path.is_symlink() for path in entries):
        print("error: candidate contains a symbolic link", file=sys.stderr)
        return 1
    packaged = {path.resolve() for path in entries if path.is_file()}
    packaged.discard(sums.resolve())
    if packaged != seen:
        print("error: unlisted files are present in candidate", file=sys.stderr)
        return 1
    print(f"verified {len(seen)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
