"""Run the frozen OMP conformance suites and emit JSON plus text reports."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from dataclasses import asdict, dataclass

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUITES = (
    "omp-spec-v0.1/tests",
    "omp-spec-v0.2-draft/tests",
    "omp-spec-v0.2-amendments/tests",
)


@dataclass
class Result:
    fixture_id: str
    outcome: str
    diagnostic: str


class Reporter:
    def __init__(self) -> None:
        self.results: list[Result] = []

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.when != "call" and not (report.when == "setup" and report.skipped):
            return
        outcome = report.outcome.upper()
        diagnostic = ""
        if report.failed:
            diagnostic = str(report.longrepr)
        elif report.skipped:
            diagnostic = str(report.longrepr)
        self.results.append(Result(report.nodeid.replace("\\", "/"), outcome, diagnostic))


def write_reports(results: list[Result], json_path: pathlib.Path, text_path: pathlib.Path) -> None:
    counts = {name: sum(result.outcome == name for result in results) for name in ("PASSED", "FAILED", "SKIPPED")}
    payload = {
        "format": "omp-conformance-report-v1",
        "suites": list(SUITES),
        "summary": counts,
        "results": [asdict(result) for result in results],
    }
    json_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = ["OMP conformance report", "", *(f"{name}: {counts[name]}" for name in counts), ""]
    for result in results:
        lines.append(f"{result.outcome:7} {result.fixture_id}")
        if result.diagnostic:
            lines.append(f"        {result.diagnostic.replace(chr(10), chr(10) + '        ')}")
    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=pathlib.Path, default=ROOT / "target/conformance/report.json")
    parser.add_argument("--text", type=pathlib.Path, default=ROOT / "target/conformance/report.txt")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    reporter = Reporter()
    pytest_args = ["-p", "no:cacheprovider", *(str(ROOT / suite) for suite in SUITES)]
    if args.quiet:
        pytest_args.insert(0, "-q")
    exit_code = pytest.main(pytest_args, plugins=[reporter])
    write_reports(reporter.results, args.json, args.text)
    print(f"wrote {args.json} and {args.text}")
    return 0 if exit_code == pytest.ExitCode.OK else 1


if __name__ == "__main__":
    raise SystemExit(main())
