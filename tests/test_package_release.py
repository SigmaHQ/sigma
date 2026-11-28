"""Exercise the release packager against a small on-disk rule collection."""

import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PACKAGER = Path(__file__).with_name("sigma-package-release.py").resolve()


class TestPackageRelease(unittest.TestCase):
    def setUp(self):
        # The packager reads version information from the enclosing Git checkout.
        tmp = tempfile.TemporaryDirectory(dir=PACKAGER.parent)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        rules = self.root / "rules"
        rules.mkdir()
        (rules / "sample.yml").write_text("level: high\nstatus: stable\n")
        self.archive = self.root / "output.zip"

    def package(self, *filters):
        return subprocess.run(
            [sys.executable, PACKAGER, "--outfile", self.archive, *filters],
            cwd=self.root,
            capture_output=True,
            text=True,
        )

    def test_empty_filters(self):
        for option, others in (
            ("--levels", ["--statuses", "stable"]),
            ("--statuses", ["--levels", "high"]),
            ("--rule-types", ["--levels", "high", "--statuses", "stable"]),
            ("--min-level", ["--statuses", "stable"]),
            ("--min-status", ["--levels", "high"]),
        ):
            with self.subTest(option=option):
                self.archive = self.root / f"{option}.zip"
                result = self.package(*others, option)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(option, result.stderr)
                self.assertFalse(self.archive.exists())

    def test_multiple_filters(self):
        result = self.package(
            "--levels", "high", "critical", "--statuses", "test", "stable",
            "--rule-types", "generic", "et",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.archive) as archive:
            self.assertCountEqual(archive.namelist(), ["rules/sample.yml", "version.txt"])

    def test_minimum_filters_default_to_generic(self):
        result = self.package("--min-level", "high", "--min-status", "stable")
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.archive) as archive:
            self.assertIn("rules/sample.yml", archive.namelist())


if __name__ == "__main__":
    unittest.main()
