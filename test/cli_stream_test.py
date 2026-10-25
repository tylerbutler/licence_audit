"""Exercise the CLI with stdout and stderr captured independently."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import uuid


ROOT = Path(__file__).resolve().parent.parent


class CliStreamTest(unittest.TestCase):
    def setUp(self):
        self.project = ROOT / "build" / f"cli_stream_test_{uuid.uuid4().hex}"
        self.project.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.project)
        (self.project / "gleam.toml").write_text(
            'name = "stream_fixture"\nversion = "1.0.0"\n'
        )

    def run_cli(self, *arguments):
        return subprocess.run(
            [str(ROOT / "licence_audit"), *arguments],
            cwd=self.project,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "NO_COLOR": "1"},
        )

    def assert_diagnostic(self, result, status=2):
        self.assertEqual(result.returncode, status, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("Error:", result.stderr)

    def test_missing_manifest_diagnostics_ignore_quiet(self):
        for command in ("", "check", "sbom", "vulns", "notices", "update"):
            with self.subTest(command=command):
                arguments = [command] if command else []
                arguments += ["--quiet", "--no-cache"]
                if command == "check":
                    arguments += ["--allow=MIT"]
                self.assert_diagnostic(self.run_cli(*arguments))

    def test_invalid_config_is_a_diagnostic(self):
        (self.project / "gleam.toml").write_text("invalid = [")
        self.assert_diagnostic(self.run_cli("--quiet", "--no-cache"))

    def test_invalid_sbom_manifest_is_a_diagnostic(self):
        (self.project / "manifest.toml").write_text("packages = [")
        self.assert_diagnostic(
            self.run_cli("sbom", "--offline", "--quiet", "--no-cache")
        )

    def test_sbom_document_and_write_failure(self):
        (self.project / "manifest.toml").write_text("packages = []\n")
        result = self.run_cli("sbom", "--offline", "--quiet", "--no-cache")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["bomFormat"], "CycloneDX")
        self.assert_diagnostic(
            self.run_cli(
                "sbom", "--offline", "--quiet", "--no-cache", "--output=."
            )
        )

    def test_gate_failure_keeps_report_on_stdout(self):
        (self.project / "manifest.toml").write_text(
            'packages = [{ name = "example", version = "1.0.0", '
            'build_tools = ["gleam"], requirements = [], '
            'otp_app = "example", source = "hex", outer_checksum = "ABC" }]\n'
            '[requirements]\nexample = ">= 1.0.0"\n'
        )
        cache_path = self.project / "metadata.dets"
        seed = subprocess.run(
            [
                "erl", "-noshell", "-pa",
                *map(str, (ROOT / "build/prod/erlang").glob("*/ebin")),
                "-eval",
                """
                Path = unicode:characters_to_binary(os:getenv("STREAM_CACHE_PATH")),
                Cache = 'licence_audit@cache':open({enabled, {some, Path}}),
                {ok, _} = 'licence_audit@cache':fetch_cached_quiet(
                    Cache, <<"example">>, <<"1.0.0">>,
                    fun(_) -> {ok, 'licence_audit@hex':licences_only([<<"MIT">>])} end),
                none = 'licence_audit@cache':close(Cache),
                halt(0).
                """,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "STREAM_CACHE_PATH": str(cache_path)},
        )
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        for licence, status in (("Apache-2.0", 1), ("MIT", 0)):
            with self.subTest(licence=licence):
                result = self.run_cli(
                    "check", "--quiet", f"--allow={licence}",
                    f"--cache-path={cache_path}",
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn("example", result.stdout)
                if status == 1:
                    self.assertIn("policy violations detected", result.stderr)
                    self.assertNotIn("example", result.stderr)
                else:
                    self.assertEqual(result.stderr, "")

    def test_help_version_and_usage_streams(self):
        for argument in ("--help", "--version"):
            result = self.run_cli(argument)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.stdout)
            self.assertEqual(result.stderr, "")
        result = self.run_cli("--not-an-option")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr)


if __name__ == "__main__":
    unittest.main()
