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
                arguments += ["--quiet"]
                if command != "vulns":
                    arguments += ["--no-cache"]
                if command == "check":
                    arguments += ["--allow=MIT"]
                self.assert_diagnostic(self.run_cli(*arguments))

    def test_invalid_config_is_a_diagnostic(self):
        (self.project / "gleam.toml").write_text("invalid = [")
        self.assert_diagnostic(self.run_cli("--quiet", "--no-cache"))

    def test_vulnerability_flags_require_scan_before_reading_manifest(self):
        for flags in (
            ["--vuln-severity=critical"],
            ["--vuln-block-unknown"],
            ["--vuln-block-unknown=false"],
            ["--vuln-severity=high", "--vuln-block-unknown"],
        ):
            for scan in ([], ["--vulns=false"]):
                with self.subTest(flags=flags, scan=scan):
                    result = self.run_cli("check", "--quiet", *flags, *scan)
                    self.assert_diagnostic(result, status=1)
                    self.assertIn("require --vulns", result.stderr)
                    self.assertNotIn("manifest", result.stderr)

    def test_help_alias_and_root_only_version(self):
        for command in ("", "check", "sbom", "vulns", "notices", "update"):
            arguments = [command] if command else []
            with self.subTest(command=command):
                help_result = self.run_cli(*arguments, "-h")
                self.assertEqual(help_result.returncode, 0, help_result.stderr)
                self.assertIn("--quiet", help_result.stdout)
                self.assertIn("-q", help_result.stdout)
                version = self.run_cli(*arguments, "--version")
                self.assertEqual(version.returncode, 1 if command else 0)

    def test_vulns_removed_cache_flags_and_short_quiet(self):
        for flag in ("--no-cache", "--cache-path=cache.sqlite3"):
            result = self.run_cli("vulns", flag)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertIn("invalid flag", result.stderr)
        for arguments in (("vulns", "-q"), ("-q", "vulns")):
            self.assert_diagnostic(self.run_cli(*arguments))

    def test_generated_payloads_ignore_color_modes(self):
        (self.project / "manifest.toml").write_text("packages = []\n")
        for command in ("sbom", "notices"):
            flags = ["--offline", "--reproducible"] if command == "sbom" else []
            with self.subTest(command=command):
                plain = self.run_cli(command, "-q", *flags, "--color=never")
                forced = self.run_cli(command, "-q", *flags, "--colour=always")
                self.assertEqual(plain.returncode, 0, plain.stderr)
                self.assertEqual(forced.returncode, 0, forced.stderr)
                self.assertEqual(forced.stdout, plain.stdout)
                self.assertNotIn("\x1b[", forced.stdout)
                destination = self.project / f"{command}.txt"
                written = self.run_cli(
                    command, "-q", *flags, "--colour=always",
                    f"--output={destination}",
                )
                self.assertEqual(written.returncode, 0, written.stderr)
                self.assertEqual(destination.read_text(), plain.stdout)

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

    def test_sbom_license_text_uses_default_notice_cache_with_metadata_override(self):
        (self.project / "manifest.toml").write_text(
            'packages = [{ name = "example", version = "1.0.0", '
            'source = "hex", outer_checksum = "ABC" }]\n'
            '[requirements]\nexample = "1.0.0"\n'
        )
        metadata_path = self.project / "metadata.sqlite3"
        cache_home = self.project / "cache"
        evaluation = """
            Mode = os:getenv("SBOM_CACHE_MODE"),
            Metadata = 'licence_audit@hex':licences_only([<<"Apache-2.0">>]),
            Text = case Mode of
                "no_cache" -> <<"Uncached SPDX text">>;
                _ -> <<"Cached SPDX text">>
            end,
            HexResult = case Mode of
                "warm" -> {error, not_found};
                _ -> {ok, Metadata}
            end,
            TextResult = case Mode of
                "warm" -> {error, fetch_network_failure};
                _ -> {ok, {some, Text}}
            end,
            lists:foreach(fun({Module, Function, Result}) ->
                {ok, {Module, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
                    beam_lib:chunks(code:which(Module), [abstract_code]),
                Replaced = lists:map(fun
                    ({function, Line, Name, 1, _}) when Name =:= Function ->
                        {function, Line, Name, 1, [
                            {clause, Line, [{var, Line, '_'}], [],
                                [erl_parse:abstract(Result)]}
                        ]};
                    (Form) -> Form
                end, Forms),
                {ok, Module, Binary} = compile:forms(Replaced, [binary]),
                {module, Module} = code:load_binary(Module, "cache_fixture", Binary)
            end, [
                {'licence_audit@hex', fetch_package_metadata_from_hex, HexResult},
                {'licence_audit@notice', fetch_spdx_text, TextResult}
            ]),
            licence_audit:main().
        """
        for mode in ("cold", "warm", "no_cache"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [
                        "erl", "-noshell", "-pa",
                        *map(str, (ROOT / "build/prod/erlang").glob("*/ebin")),
                        "-eval", evaluation, "-extra", "sbom", "--license-text",
                        "--quiet", f"--cache-path={metadata_path}",
                        *(["--no-cache"] if mode == "no_cache" else []),
                    ],
                    cwd=self.project, capture_output=True, text=True, timeout=30,
                    env={
                        **os.environ, "NO_COLOR": "1",
                        "XDG_CACHE_HOME": str(cache_home), "SBOM_CACHE_MODE": mode,
                    },
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")
                component = json.loads(result.stdout)["components"][0]
                licence = component["licenses"][0]["license"]
                self.assertEqual(licence["id"], "Apache-2.0")
                self.assertEqual(licence["text"]["contentType"], "text/plain")
                self.assertEqual(
                    licence["text"]["content"],
                    "Uncached SPDX text" if mode == "no_cache" else "Cached SPDX text",
                )
                metadata_files = list(metadata_path.glob("*.json"))
                self.assertEqual(len(metadata_files), 1)
                self.assertEqual(
                    json.loads(metadata_files[0].read_text())["key"], "example@1.0.0"
                )
                notice_files = list((cache_home / "licence_audit").glob("notices-v*/*.json"))
                self.assertEqual(len(notice_files), 1)
                entry = json.loads(notice_files[0].read_text())
                self.assertTrue(entry["key"].startswith("spdx:"))
                self.assertTrue(entry["key"].endswith(":license:Apache-2.0"))
                self.assertEqual(entry["value"], "Cached SPDX text")
                if mode == "cold":
                    cached_files = {
                        file: file.read_bytes() for file in metadata_files + notice_files
                    }
                else:
                    self.assertEqual(
                        {file: file.read_bytes() for file in metadata_files + notice_files},
                        cached_files,
                    )

    def test_gate_failure_keeps_report_on_stdout(self):
        (self.project / "manifest.toml").write_text(
            'packages = [{ name = "example", version = "1.0.0", '
            'build_tools = ["gleam"], requirements = [], '
            'otp_app = "example", source = "hex", outer_checksum = "ABC" }]\n'
            '[requirements]\nexample = ">= 1.0.0"\n'
        )
        cache_path = self.project / "metadata"
        seed = subprocess.run(
            [
                "erl", "-noshell", "-pa",
                *map(str, (ROOT / "build/prod/erlang").glob("*/ebin")),
                "-eval",
                """
                Path = unicode:characters_to_binary(os:getenv("STREAM_CACHE_PATH")),
                Cache = 'licence_audit@cache':open({enabled, {some, Path}}),
                {{ok, _}, none} = 'licence_audit@cache':fetch_cached_quiet(
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
            for quiet in (False, True):
                with self.subTest(licence=licence, quiet=quiet):
                    result = self.run_cli(
                        "check", f"--allow={licence}",
                        f"--cache-path={cache_path}",
                        *(["--quiet"] if quiet else []),
                    )
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertIn("example", result.stdout)
                    self.assertNotIn("ERROR", result.stderr)
                    self.assertNotIn("policy violations detected", result.stderr)
                    self.assertEqual(
                        "Dependency licence audit failed" in result.stdout,
                        status == 1,
                    )
                    if quiet:
                        self.assertEqual(result.stderr, "")

    def test_vulnerability_gate_and_operational_failure_streams(self):
        (self.project / "manifest.toml").write_text(
            'packages = [{ name = "example", version = "1.0.0", '
            'build_tools = ["gleam"], requirements = [], '
            'otp_app = "example", source = "hex", outer_checksum = "ABC" }]\n'
            '[requirements]\nexample = ">= 1.0.0"\n'
        )
        # Replace only fetch functions in a fresh VM, retaining the real OSV
        # formatting/severity functions and main's stream dispatch.
        evaluation = """
            Metadata = 'licence_audit@hex':licences_only([<<"MIT">>]),
            HexForms = [
                {attribute, 1, module, 'licence_audit@hex'},
                {attribute, 1, export, [{fetch_package_metadata_from_hex, 1}]},
                {function, 1, fetch_package_metadata_from_hex, 1, [
                    {clause, 1, [{var, 1, '_'}], [],
                        [erl_parse:abstract({ok, Metadata})]}
                ]}
            ],
            {ok, Hex, HexBinary} = compile:forms(HexForms, [binary]),
            {module, Hex} = code:load_binary(Hex, "stream_fixture", HexBinary),
            Mode = os:getenv("STREAM_OSV_MODE"),
            Severity = case Mode of "unknown" -> unknown_severity; _ -> high end,
            Batch = case Mode of
                "batch_failure" -> {error, network_failure};
                _ -> {ok, [{batch_entry, <<"pkg:hex/example@1.0.0">>,
                    [<<"CVE-STREAM-0001">>]}]}
            end,
            Detail = case Mode of
                "detail_failure" -> {error, not_found};
                _ -> {ok, {vulnerability, <<"CVE-STREAM-0001">>, [],
                    <<"Fixture advisory">>, Severity, []}}
            end,
            Osv = 'licence_audit@osv',
            {ok, {Osv, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
                beam_lib:chunks(code:which(Osv), [abstract_code]),
            Replaced = lists:map(fun
                ({function, Line, Name, 1, _}) when
                    Name =:= query_batch_from_osv;
                    Name =:= fetch_vulnerability_from_osv ->
                    Result = case Name of
                        query_batch_from_osv -> Batch;
                        fetch_vulnerability_from_osv -> Detail
                    end,
                    {function, Line, Name, 1, [
                        {clause, Line, [{var, Line, '_'}], [],
                            [erl_parse:abstract(Result)]}
                    ]};
                (Form) -> Form
            end, Forms),
            {ok, Osv, OsvBinary} = compile:forms(Replaced, [binary]),
            {module, Osv} = code:load_binary(Osv, "stream_fixture", OsvBinary),
            licence_audit:main().
        """
        cases = (
            ("high", False, 1),
            ("unknown", False, 1),
            ("batch_failure", False, 2),
            ("detail_failure", False, 2),
            ("batch_failure", True, 2),
            ("detail_failure", True, 2),
        )
        for mode, deny_licence, status in cases:
            for quiet in (False, True):
                with self.subTest(mode=mode, deny_licence=deny_licence, quiet=quiet):
                    arguments = ["check", "--allow=MIT", "--vulns", "--no-cache"]
                    if mode == "unknown":
                        arguments += ["--vuln-block-unknown"]
                    if deny_licence:
                        arguments += ["--deny=MIT"]
                    if quiet:
                        arguments += ["--quiet"]
                    result = subprocess.run(
                        [
                            "erl", "-noshell", "-pa",
                            *map(str, (ROOT / "build/prod/erlang").glob("*/ebin")),
                            "-eval", evaluation, "-extra", *arguments,
                        ],
                        cwd=self.project, capture_output=True, text=True,
                        timeout=30,
                        env={
                            **os.environ, "NO_COLOR": "1",
                            "STREAM_OSV_MODE": mode,
                        },
                    )
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                    self.assertIn("example", result.stdout)
                    if status == 1:
                        self.assertIn("CVE-STREAM-0001", result.stdout)
                        self.assertIn("Vulnerability check failed:", result.stdout)
                        self.assertNotIn("ERROR", result.stderr)
                        if quiet:
                            self.assertEqual(result.stderr, "")
                    else:
                        diagnostic = (
                            "OSV request failed" if mode == "batch_failure"
                            else "failed to fetch OSV advisory details"
                        )
                        self.assertNotIn(diagnostic, result.stdout)
                        self.assertIn(diagnostic, result.stderr)
                        self.assertEqual(result.stderr.count("ERROR"), 1)
                        self.assertNotIn("Dependency licence audit failed", result.stdout)
                        if mode == "detail_failure":
                            self.assertNotIn("CVE-STREAM-0001", result.stdout)
                            self.assertIn("CVE-STREAM-0001: OSV resource not found", result.stderr)
                        if quiet:
                            self.assertNotIn("INFO", result.stderr)
                            self.assertNotIn("WARN", result.stderr)

    def test_unavailable_cache_preserves_reports_and_sbom_stdout(self):
        (self.project / "manifest.toml").write_text("packages = []\n")
        blocker = self.project / "cache"
        blocker.write_text("not a directory")
        env = {**os.environ, "XDG_CACHE_HOME": str(blocker)}
        for arguments in (["check", "--allow=MIT"], ["sbom", "--offline"]):
            for no_cache in (False, True):
                with self.subTest(command=arguments[0], no_cache=no_cache):
                    flags = ["--quiet", "--no-cache"] if no_cache else []
                    result = subprocess.run(
                        [str(ROOT / "licence_audit"), *arguments, *flags], cwd=self.project,
                        env=env, capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if arguments[0] == "sbom":
                        self.assertEqual(json.loads(result.stdout)["bomFormat"], "CycloneDX")
                    else:
                        self.assertTrue(result.stdout)
                        self.assertNotIn("cache", result.stdout.lower())
                    if no_cache:
                        self.assertEqual(result.stderr, "")
                    else:
                        self.assertIn("Unable to open licence cache", result.stderr)
                    self.assertEqual(blocker.read_text(), "not a directory")

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

    def test_unexpected_cli_exceptions_exit_two_without_raw_trace(self):
        evaluation = """
            [ClassName] = init:get_plain_arguments(),
            Class = list_to_existing_atom(ClassName),
            Forms = [
                {attribute, 1, module, args_ffi},
                {attribute, 1, export, [{arguments, 0}]},
                {function, 1, arguments, 0, [
                    {clause, 1, [], [], [
                        {call, 1, {remote, 1, {atom, 1, erlang}, {atom, 1, Class}},
                            [{atom, 1, unexpected_cli_failure}]}
                    ]}
                ]}
            ],
            {ok, Module, Binary} = compile:forms(Forms, [binary]),
            {module, Module} = code:load_binary(Module, "exception_fixture", Binary),
            licence_audit:main().
        """
        for exception_class in ("error", "throw", "exit"):
            with self.subTest(exception_class=exception_class):
                result = subprocess.run(
                    [
                        "erl", "-noshell", "-pa",
                        *map(str, (ROOT / "build/prod/erlang").glob("*/ebin")),
                        "-eval", evaluation, "-extra", exception_class,
                    ],
                    cwd=self.project,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env={**os.environ, "NO_COLOR": "1"},
                )
                self.assert_diagnostic(result)
                self.assertEqual(
                    result.stderr,
                    "Error: Unexpected Erlang exception: "
                    f"{exception_class}: unexpected_cli_failure\n",
                )

    def test_missing_ca_bundle_exits_two_in_escript(self):
        (self.project / "manifest.toml").write_text(
            'packages = [{ name = "gleam_stdlib", version = "0.60.0", '
            'build_tools = ["gleam"], requirements = [], '
            'otp_app = "gleam_stdlib", source = "hex", outer_checksum = "ABC" }]\n'
            '[requirements]\ngleam_stdlib = ">= 0.60.0"\n'
        )
        for arguments in (["check", "--allow=MIT", "--no-cache"], ["vulns"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [str(ROOT / "licence_audit"), *arguments],
                    cwd=self.project,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env={
                        **os.environ,
                        "NO_COLOR": "1",
                        "ERL_FLAGS": "-public_key cacerts_path [47,110,111]",
                    },
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("failed_load_cacerts", result.stderr)
                self.assertIn("enoent", result.stderr)
                self.assertNotIn("runtime error:", result.stderr.lower())
                self.assertNotIn("stack trace", result.stderr.lower())
                self.assertNotIn("runtime terminating", result.stderr.lower())
                self.assertFalse((self.project / "erl_crash.dump").exists())


if __name__ == "__main__":
    unittest.main()
