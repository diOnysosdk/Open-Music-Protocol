import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


class Pi400PathTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX shell environment regression")
    def test_validate_loads_rustup_path_for_noninteractive_ssh(self):
        shell = shutil.which("sh")
        self.assertIsNotNone(shell)
        repo = Path(__file__).resolve().parents[2]

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / "home"
            cargo_bin = home / ".cargo" / "bin"
            cargo_bin.mkdir(parents=True)
            capture = base / "path.txt"
            output = base / "evidence"

            (home / ".cargo" / "env").write_text(
                'export PATH="$HOME/.cargo/bin:$PATH"\n', encoding="utf-8"
            )
            fake_python = cargo_bin / "python3"
            fake_python.write_text(
                "#!/bin/sh\n"
                'printf "%s" "$PATH" > "$OMP_PATH_CAPTURE"\n'
                'mkdir -p "$3"\n'
                'touch "$3/evidence.json" "$3/report.md"\n'
                "exit 0\n",
                encoding="utf-8",
            )
            fake_python.chmod(fake_python.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "OMP_PATH_CAPTURE": str(capture),
                    "PATH": "/usr/bin:/bin",
                }
            )
            result = subprocess.run(
                [shell, "scripts/pi400/validate.sh", str(output)],
                cwd=repo,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            inherited_path = capture.read_text(encoding="utf-8").split(os.pathsep)
            self.assertEqual(Path(inherited_path[0]), cargo_bin)
            self.assertTrue((output / "evidence.json").is_file())
            self.assertTrue((output / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
