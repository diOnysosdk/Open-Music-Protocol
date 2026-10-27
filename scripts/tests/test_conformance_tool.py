import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("conformance", ROOT / "scripts/conformance.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ConformanceReportTests(unittest.TestCase):
    def test_reports_have_stable_outcomes_and_fixture_ids(self) -> None:
        results = [
            MODULE.Result("suite/test_file.py::test_case", "PASSED", ""),
            MODULE.Result("suite/test_file.py::test_skip", "SKIPPED", "requires privilege"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            json_path = pathlib.Path(directory) / "report.json"
            text_path = pathlib.Path(directory) / "report.txt"
            MODULE.write_reports(results, json_path, text_path)
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["format"], "omp-conformance-report-v1")
            self.assertEqual(report["summary"]["PASSED"], 1)
            self.assertEqual(report["summary"]["SKIPPED"], 1)
            self.assertIn("fixture_id", report["results"][0])
            self.assertIn("SKIPPED", text_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
