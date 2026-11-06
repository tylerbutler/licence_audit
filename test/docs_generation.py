"""Check the documentation generator's filesystem contract in an isolated copy."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
EBINS = sorted((ROOT / "build/dev/erlang").glob("*/ebin"))


class DocsGenerationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="licence-audit-docs-")
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.docs = self.root / "website/src/pages/docs"
        shutil.copytree(ROOT / "website/src/pages/docs", self.docs)

    def run_generator(self, check=False):
        return subprocess.run(
            [
                "erl",
                "-noshell",
                "-pa",
                *(str(path) for path in EBINS),
                "-s",
                "licence_audit@gen_docs",
                "main",
                "-s",
                "init",
                "stop",
                "-extra",
                *(["--check"] if check else []),
            ],
            cwd=self.root,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def snapshot(self):
        return {path.name: path.read_bytes() for path in self.docs.glob("*.md")}

    def test_idempotence_and_read_only_drift_check(self):
        initial = self.snapshot()
        result = self.run_generator(check=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), initial)
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), initial)

        page = self.docs / "sbom.md"
        before, reference = page.read_text().split("<!-- cli-reference -->")
        page.write_text(
            before
            + "<!-- cli-reference -->"
            + reference.replace("`--license-text`", "`--stale`")
        )
        stale = self.snapshot()
        result = self.run_generator(check=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("would change", result.stderr)
        self.assertEqual(self.snapshot(), stale)
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), initial)

    def test_invalid_markers_and_missing_pages_do_not_write(self):
        page = self.docs / "vulns.md"
        original = page.read_text()
        page.write_text(original.replace("<!-- cli-referencestop -->", ""))
        invalid = self.snapshot()
        result = self.run_generator()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("stop marker", result.stderr)
        self.assertEqual(self.snapshot(), invalid)

        page.unlink()
        missing = self.snapshot()
        result = self.run_generator()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("could not read", result.stderr)
        self.assertEqual(self.snapshot(), missing)


if __name__ == "__main__":
    unittest.main()
