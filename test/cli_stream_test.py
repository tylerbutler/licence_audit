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

    def test_notices_filters_keep_reports_and_diagnostics_separate(self):
        project_config = (
            '[dev-dependencies]\nlocal = { path = "local" }\n'
            '[tools.licence_audit.notices]\ninclude = ["local"]\n'
        )
        (self.project / "gleam.toml").write_text(project_config)
        (self.project / "manifest.toml").write_text(
            'packages = [{ name = "local", version = "1.0.0", '
            'source = "path", path = "local" }]\n'
            '[requirements]\nlocal = { path = "local" }\n'
        )
        cache_path = self.project / "metadata.dets"
        result = self.run_cli("notices", "--quiet", f"--cache-path={cache_path}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Third-party licences", result.stdout)
        self.assertNotIn("Products using this licence", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertFalse(cache_path.exists())

        (self.project / "local").mkdir()
        (self.project / "local/LICENSE").write_text("Local dev licence\n")
        result = self.run_cli("notices", "--include-dev", "--quiet", "--no-cache")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("local 1.0.0", result.stdout)
        self.assertIn("Local dev licence", result.stdout)
        self.assertEqual(result.stderr, "")

        (self.project / "gleam.toml").write_text(
            project_config + 'exclude = ["stale"]\n'
        )
        result = self.run_cli("notices", "--quiet", f"--cache-path={cache_path}")
        self.assert_diagnostic(result)
        self.assertIn("Unknown locked package names", result.stderr)
        self.assertFalse(cache_path.exists())

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

    def test_unloadable_sqlite_keeps_sbom_stdout_valid(self):
        binary = self.project / "licence_audit"
        shutil.copy2(ROOT / "licence_audit", binary)
        sidecar = self.project / "sqlite_native/esqlite"
        shutil.copytree(ROOT / "sqlite_native/esqlite", sidecar)
        for library in (sidecar / "priv").rglob("*"):
            if library.is_file() and library.suffix in (".so", ".dll", ".dylib"):
                library.write_bytes(b"Unloadable native library fixture")
        (self.project / "manifest.toml").write_text("packages = []\n")
        env = {**os.environ, "XDG_CACHE_HOME": str(self.project / "cache")}
        env.pop("ERL_LIBS", None)
        result = subprocess.run(
            [str(binary), "sbom", "--offline", "--quiet"],
            cwd=self.project, env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["bomFormat"], "CycloneDX")
        self.assertIn("Failed to load NIF library", result.stderr)

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

    def test_incomplete_reports_exit_two_on_stdout(self):
        packages = [
            '{ name = "' + name + '", version = "1.0.0", '
            'build_tools = ["gleam"], requirements = [], '
            'otp_app = "' + name + '", source = "hex", outer_checksum = "ABC" }'
            for name in ("healthy", "unavailable")
        ]
        (self.project / "manifest.toml").write_text(
            "packages = [" + ", ".join(packages) + "]\n"
            '[requirements]\nhealthy = ">= 1.0.0"\nunavailable = ">= 1.0.0"\n'
        )
        # Replace only Hex fetching in a fresh VM; exercise the real main/dispatch.
        evaluation = """
            Metadata = 'licence_audit@hex':licences_only([<<"MIT">>]),
            Forms = [
                {attribute, 1, module, 'licence_audit@hex'},
                {attribute, 1, export, [{fetch_package_metadata_from_hex, 1}]},
                {function, 1, fetch_package_metadata_from_hex, 1, [
                    {clause, 1, [erl_parse:abstract(<<"healthy">>)], [],
                        [erl_parse:abstract({ok, Metadata})]},
                    {clause, 1, [{var, 1, '_'}], [],
                        [erl_parse:abstract({error,
                            {network_failure, <<"fixture metadata failure">>}})]}
                ]}
            ],
            {ok, Module, Binary} = compile:forms(Forms, [binary]),
            {module, Module} = code:load_binary(Module, "stream_fixture", Binary),
            licence_audit:main().
        """
        for command in ([], ["check", "--allow=MIT"]):
            with self.subTest(command=command):
                result = subprocess.run(
                    [
                        "erl", "-noshell", "-pa",
                        *map(str, (ROOT / "build/prod/erlang").glob("*/ebin")),
                        "-eval", evaluation, "-extra",
                        *command, "--quiet", "--no-cache",
                    ],
                    cwd=self.project,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env={**os.environ, "NO_COLOR": "1"},
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("healthy", result.stdout)
                self.assertIn("MIT", result.stdout)
                self.assertIn("unavailable", result.stdout)
                self.assertIn("fixture metadata failure", result.stdout)
                self.assertIn("package metadata could not be fetched", result.stderr)
                self.assertNotIn("healthy", result.stderr)


if __name__ == "__main__":
    unittest.main()
