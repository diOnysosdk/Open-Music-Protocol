#!/usr/bin/env python3
"""Generate deterministic CycloneDX JSON from Cargo's locked dependency graph."""

import json
import pathlib
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: generate-desktop-sbom.py OUTPUT", file=sys.stderr)
        return 2
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            text=True,
            encoding="utf-8",
        )
    )
    packages = sorted(metadata["packages"], key=lambda item: (item["name"], item["version"]))
    components = []
    for package in packages:
        component = {"type": "library", "name": package["name"], "version": package["version"]}
        if package.get("license"):
            component["licenses"] = [{"expression": package["license"]}]
        if package["source"] and package["source"].startswith("registry+"):
            component["purl"] = f"pkg:cargo/{package['name']}@{package['version']}"
        components.append(component)
    document = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "omp-desktop", "version": "0.1.0"}},
        "components": components,
    }
    pathlib.Path(sys.argv[1]).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
