import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts" / "verify-alpha.py"
AUDIT = ROOT / "scripts" / "audit-alpha.py"


class AlphaToolTests(unittest.TestCase):
    def run_tool(self, tool: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(tool), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_verifier_accepts_complete_inventory_and_rejects_unlisted_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            payload = root / "payload.txt"
            payload.write_bytes(b"deterministic\n")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            (root / "SHA256SUMS").write_text(f"{digest}  payload.txt\n", encoding="utf-8")
            self.assertEqual(self.run_tool(VERIFY, str(root)).returncode, 0)
            (root / "unlisted.txt").write_text("unexpected", encoding="utf-8")
            result = self.run_tool(VERIFY, str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unlisted files", result.stderr)

    def test_verifier_rejects_traversal_and_invalid_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "SHA256SUMS").write_text(f"{'0' * 64}  ../outside\n", encoding="utf-8")
            self.assertNotEqual(self.run_tool(VERIFY, str(root)).returncode, 0)
            (root / "SHA256SUMS").write_text("not-a-hash  file\n", encoding="utf-8")
            self.assertNotEqual(self.run_tool(VERIFY, str(root)).returncode, 0)

    def test_auditor_rejects_private_key_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for relative in sorted(__import__("runpy").run_path(str(AUDIT))["REQUIRED"]):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}" if path.suffix == ".json" else "fixture", encoding="utf-8")
            (root / "omp").write_text("binary", encoding="utf-8")
            (root / "omp-player").write_text("binary", encoding="utf-8")
            for crate in __import__("runpy").run_path(str(AUDIT))["CRATES"]:
                path = root / "sbom" / f"{crate}.cdx.json"
                path.parent.mkdir(exist_ok=True)
                path.write_text("{}", encoding="utf-8")
            secret = root / "samples" / "fixture-index.json"
            secret.write_text(json.dumps({"private_key_base64url": "test-only"}), encoding="utf-8")
            result = self.run_tool(AUDIT, str(root), "linux")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private field", result.stderr)


if __name__ == "__main__":
    unittest.main()
