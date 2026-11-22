"""Exercise the CLI with stdout and stderr captured independently."""

from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest
import uuid


ROOT = Path(__file__).resolve().parent.parent
HEX_ARCHIVE = ROOT / "test/fixtures/sbom_metadata/hex.tar"
HEX_CHECKSUM = hashlib.sha256(HEX_ARCHIVE.read_bytes()).hexdigest().upper()
EBINS = sorted(map(str, (ROOT / "build/prod/erlang").glob("*/ebin")))


class CliStreamTest(unittest.TestCase):
    def setUp(self):
        self.project = ROOT / "build" / f"cli_stream_test_{uuid.uuid4().hex}"
        self.project.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.project)
        (self.project / "gleam.toml").write_text(
            'name = "stream_fixture"\nversion = "1.0.0"\n'
            '[tools.licence_audit]\nallow = ["MIT"]\n'
        )

    def run_cli(
        self, *arguments, environment=None, fixture=None,
        stdout_tty=False, stderr_tty=False,
    ):
        env = {**os.environ, "NO_COLOR": "1"}
        if environment is not None:
            for name in ("NO_COLOR", "FORCE_COLOR", "TERM", "CI", "COLORTERM"):
                env.pop(name, None)
            env.update(environment)
        command = [str(ROOT / "licence_audit"), *arguments]
        if fixture is not None:
            command = [
                "erl", "-noshell", "-pa", *EBINS, "-pa", str(fixture),
                "-eval", "licence_audit:main().", "-extra", *arguments,
            ]
        if stdout_tty or stderr_tty:
            return self.run_cli_with_terminals(
                command, env, stdout_tty, stderr_tty,
            )
        return subprocess.run(
            command,
            cwd=self.project,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def run_cli_with_terminals(self, command, env, stdout_tty, stderr_tty):
        def read_terminal(master):
            chunks = []
            while True:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode().replace("\r\n", "\n")

        terminals = {}
        with ThreadPoolExecutor(max_workers=2) as readers:
            try:
                for stream, enabled in (
                    ("stdout", stdout_tty), ("stderr", stderr_tty),
                ):
                    if enabled:
                        master, slave = os.openpty()
                        terminals[stream] = (
                            master, slave, readers.submit(read_terminal, master),
                        )
                try:
                    result = subprocess.run(
                        command, cwd=self.project, text=True, env=env, timeout=30,
                        **{
                            stream: terminals[stream][1]
                            if stream in terminals else subprocess.PIPE
                            for stream in ("stdout", "stderr")
                        },
                    )
                finally:
                    for _, slave, _ in terminals.values():
                        os.close(slave)
                for stream, (_, _, reader) in terminals.items():
                    setattr(result, stream, reader.result(timeout=5))
                return result
            finally:
                for master, _, _ in terminals.values():
                    os.close(master)

    def compile_fixture(self, evaluation, environment):
        directory = self.project / f"fixture_{uuid.uuid4().hex}"
        directory.mkdir()
        result = subprocess.run(
            ["erl", "-noshell", "-pa", *EBINS, "-eval", evaluation],
            cwd=self.project, capture_output=True, text=True, timeout=30,
            env={
                **os.environ, **environment,
                "STREAM_FIXTURE_EBIN": str(directory),
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        return directory

    def assert_diagnostic(self, result, status=2):
        self.assertEqual(result.returncode, status, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("Error:", result.stderr)

    def test_help_outside_project_does_not_open_cache(self):
        (self.project / "gleam.toml").unlink()
        cache = self.project / "unused-cache"
        env = {
            **os.environ, "HOME": str(self.project / "unused-home"),
            "XDG_CACHE_HOME": str(cache), "NO_COLOR": "1",
        }
        for arguments in (["--help"], ["-h"], ["--version"], ["report", "-h"]):
            result = subprocess.run(
                [str(ROOT / "licence_audit"), *arguments],
                cwd=self.project, env=env, capture_output=True, text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertTrue(result.stdout)
            if arguments != ["--version"]:
                self.assertIn("report", result.stdout)
                self.assertIn("USAGE:", result.stdout)
            self.assertFalse(cache.exists())
            self.assertFalse((self.project / "unused-home").exists())

    def assert_help_stream(self, result, usage_error, colored):
        destination = result.stderr if usage_error else result.stdout
        other = result.stdout if usage_error else result.stderr
        self.assertEqual(result.returncode, 2 if usage_error else 0, destination)
        self.assertEqual(other, "")
        self.assertIn("USAGE:", destination)
        self.assertEqual("\x1b" in destination, colored, destination)
        return destination

    def test_short_version_outside_project_matches_long_version_without_cache(self):
        (self.project / "gleam.toml").unlink()
        environment = {
            "HOME": str(self.project / "unused-home"),
            "XDG_CACHE_HOME": str(self.project / "unused-cache"),
            "NO_COLOR": "1",
        }
        canonical = self.run_cli("--version", environment=environment)
        alias = self.run_cli("-V", environment=environment)
        self.assertEqual(alias.returncode, 0, alias.stderr)
        self.assertTrue(alias.stdout)
        self.assertEqual(alias.stdout, canonical.stdout)
        self.assertEqual(alias.stderr, "")
        self.assertFalse((self.project / "unused-home").exists())
        self.assertFalse((self.project / "unused-cache").exists())

    def test_short_output_writes_literal_flag_shaped_paths(self):
        (self.project / "manifest.toml").write_text("packages = []\n")
        for command in ("sbom", "notices"):
            flags = ["--offline", "--reproducible"] if command == "sbom" else []
            canonical = self.run_cli(command, "-q", "--no-cache", *flags)
            self.assertEqual(canonical.returncode, 0, canonical.stderr)
            for value in ("output.txt", "-V", "-v", "-h", "-o"):
                with self.subTest(command=command, value=value):
                    result = self.run_cli(
                        command, "-q", "--no-cache", *flags, "-o", value,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(
                        (self.project / value).read_text(), canonical.stdout,
                    )

    def test_new_short_alias_usage_errors_precede_io(self):
        for arguments in (
            ["-V", "--unknown"],
            ["unknown-command", "-V"],
            ["report", "-V"],
            ["check", "-V"],
            ["update", "-V"],
            ["sbom", "-V"],
            ["vulns", "-V"],
            ["notices", "-V"],
            ["-o", "out"],
            ["report", "-o", "out"],
            ["sbom", "-o"],
            ["notices", "-o"],
            ["sbom", "-o", "--"],
            ["sbom", "-oPATH"],
            ["sbom", "-o=PATH"],
            ["sbom", "-qv"],
            ["sbom", "-vV"],
        ):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assert_diagnostic(result)
                self.assertNotIn("Could not read", result.stderr)
                self.assertFalse((self.project / "out").exists())

    def test_help_pipe_color_modes_and_aliases_on_every_command(self):
        for command in ([], ["report"], ["check"], ["update"], ["sbom"], ["vulns"], ["notices"]):
            for flags, environment, colored in (
                ([], {"TERM": "xterm-256color"}, False),
                (["--color=always"], {"NO_COLOR": "1"}, True),
                (["--colour", "ALWAYS"], {"TERM": "dumb"}, True),
                (["--colour=never"], {"FORCE_COLOR": "3"}, False),
                (["--color", "never"], {"FORCE_COLOR": "1"}, False),
            ):
                for usage_error in (False, True):
                    with self.subTest(command=command, flags=flags, error=usage_error):
                        suffix = "--unknown" if usage_error else "-h"
                        result = self.run_cli(
                            *command, *flags, suffix, environment=environment,
                        )
                        self.assert_help_stream(result, usage_error, colored)

    def test_help_auto_uses_report_environment_policy_in_pipes(self):
        for environment, colored in (
            ({}, False),
            ({"NO_COLOR": "1", "FORCE_COLOR": "3"}, False),
            ({"FORCE_COLOR": "0", "TERM": "xterm-256color"}, False),
            ({"FORCE_COLOR": "1"}, True),
            ({"FORCE_COLOR": "2", "CI": "1"}, True),
            ({"FORCE_COLOR": "3", "TERM": "dumb"}, True),
            ({"TERM": "xterm-256color"}, False),
            ({"COLORTERM": "truecolor"}, False),
            ({"CI": "1", "TERM": "xterm-256color"}, False),
        ):
            for usage_error in (False, True):
                with self.subTest(environment=environment, error=usage_error):
                    result = self.run_cli(
                        "--color=auto",
                        "--unknown" if usage_error else "--help",
                        environment=environment,
                    )
                    self.assert_help_stream(result, usage_error, colored)

    @unittest.skipUnless(hasattr(os, "openpty"), "requires POSIX terminals")
    def test_help_pipe_terminal_matrix_uses_actual_destination(self):
        for stdout_tty, stderr_tty in (
            (False, False), (True, False), (False, True), (True, True),
        ):
            for usage_error in (False, True):
                for mode, environment, forced in (
                    ("auto", {"TERM": "xterm-256color"}, None),
                    ("auto", {"TERM": "xterm-256color", "CI": "1"}, None),
                    ("always", {"NO_COLOR": "1", "TERM": "dumb"}, True),
                    ("never", {"FORCE_COLOR": "3"}, False),
                ):
                    with self.subTest(
                        stdout_tty=stdout_tty, stderr_tty=stderr_tty,
                        error=usage_error, mode=mode, environment=environment,
                    ):
                        colored = (
                            stderr_tty if usage_error else stdout_tty
                        ) if forced is None else forced
                        result = self.run_cli(
                            f"--color={mode}",
                            "--unknown" if usage_error else "--help",
                            environment=environment,
                            stdout_tty=stdout_tty, stderr_tty=stderr_tty,
                        )
                        self.assert_help_stream(result, usage_error, colored)

    @unittest.skipUnless(hasattr(os, "openpty"), "requires POSIX terminals")
    def test_help_terminal_environment_disables_or_enables_auto(self):
        for environment, colored in (
            ({"NO_COLOR": "1", "TERM": "xterm-256color"}, False),
            ({"FORCE_COLOR": "0", "COLORTERM": "truecolor"}, False),
            ({"TERM": "dumb", "COLORTERM": "truecolor"}, False),
            ({"COLORTERM": "truecolor"}, True),
            ({"COLORTERM": "24bit"}, True),
            ({"TERM": "xterm"}, False),
            ({"TERM": "xterm", "CI": "1"}, True),
        ):
            for usage_error in (False, True):
                with self.subTest(environment=environment, error=usage_error):
                    result = self.run_cli(
                        "--unknown" if usage_error else "-h",
                        environment=environment, stdout_tty=True, stderr_tty=True,
                    )
                    self.assert_help_stream(result, usage_error, colored)

    def test_help_color_does_not_scan_literal_option_values(self):
        for command, flag in (([], "--manifest"), (["sbom"], "--output")):
            for value in ("--color=always", "--colour=always"):
                for flags in ([flag, value], [f"{flag}={value}"]):
                    for usage_error in (False, True):
                        with self.subTest(command=command, flags=flags, error=usage_error):
                            result = self.run_cli(
                                *command, *flags,
                                "--unknown" if usage_error else "--help",
                                environment={"TERM": "xterm-256color"},
                            )
                            self.assert_help_stream(result, usage_error, False)

    def test_help_color_preserves_plain_layout_and_usage_diagnostics(self):
        for usage_error in (False, True):
            suffix = "--unknown" if usage_error else "--help"
            plain = self.assert_help_stream(
                self.run_cli("--color=never", suffix), usage_error, False,
            )
            colored = self.assert_help_stream(
                self.run_cli("--color=always", suffix), usage_error, True,
            )
            self.assertEqual(re.sub(r"\x1b\[[0-9;]*m", "", colored), plain)

    def test_default_report_matches_named_report_with_root_options(self):
        (self.project / "manifest.toml").write_text("packages = []\n")
        (self.project / "locked.toml").write_text("packages = []\n")
        (self.project / "policy.toml").write_text(
            '[tools.licence_audit]\nallow = ["MIT"]\n'
        )
        environment = {
            "HOME": str(self.project / "home"),
            "XDG_CACHE_HOME": str(self.project / "cache"),
            "NO_COLOR": "1",
        }
        for flags in (
            [],
            [
                "--manifest=locked.toml", "--config=policy.toml",
                "--scope=all", "--cache-dir=explicit-cache", "-v", "--colour=never",
            ],
        ):
            with self.subTest(flags=flags):
                root = self.run_cli(*flags, environment=environment)
                named = self.run_cli("report", *flags, environment=environment)
                self.assertEqual(root.returncode, 0, root.stderr)
                self.assertEqual(
                    (root.returncode, root.stdout),
                    (named.returncode, named.stdout),
                )
                self.assertIn("Skipped non-Hex packages: 0", root.stdout)
        result = self.run_cli("audit")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_missing_manifest_diagnostics_ignore_quiet(self):
        for command in ("", "report", "check", "sbom", "vulns", "notices", "update"):
            with self.subTest(command=command):
                arguments = [command] if command else []
                arguments += ["--quiet"]
                if command != "vulns":
                    arguments += ["--no-cache"]
                self.assert_diagnostic(self.run_cli(*arguments))

    def test_usage_error_classes_exit_two_before_io(self):
        for arguments, diagnostic in (
            (["--unknown"], "unknown"),
            (["unknown-command"], "invalid number of arguments"),
            (["check", "unexpected"], "invalid number of arguments"),
            (["check", "--scope=invalid"], "must be one of"),
            (["report", "--color=invalid"], "color"),
            (["check", "--manifest"], "has no assigned value"),
            (["report", "--quiet", "--verbose"], "cannot be used together"),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(diagnostic, result.stderr)
                self.assertNotIn("Could not read", result.stderr)

    def test_conflicting_paths_and_enabled_booleans_exit_two_before_io(self):
        for commands, path_flag, boolean_flag, diagnostic in (
            (
                ([], ["report"], ["check"], ["notices"], ["vulns"]),
                "--config=missing-policy.toml", "--ignore-config",
                "--config and --ignore-config cannot be used together",
            ),
            (
                ([], ["report"], ["check"], ["update"], ["sbom"], ["notices"]),
                "--cache-dir=unused-cache", "--no-cache",
                "--no-cache and --cache-dir cannot be used together",
            ),
        ):
            for command in commands:
                for suffix in ("", "=true"):
                    with self.subTest(command=command, flag=boolean_flag + suffix):
                        result = self.run_cli(*command, path_flag, boolean_flag + suffix)
                        self.assert_diagnostic(result)
                        self.assertEqual(result.stderr, f"Error: {diagnostic}\n")
                        self.assertFalse((self.project / "unused-cache").exists())

    def test_invalid_config_is_a_diagnostic(self):
        (self.project / "gleam.toml").write_text("invalid = [")
        self.assert_diagnostic(self.run_cli("report", "--quiet", "--no-cache"))

    def test_removed_policy_flags_keep_usage_errors_on_stderr(self):
        for command in ([], ["report"], ["check"]):
            for name in ("allow", "deny"):
                with self.subTest(command=command, name=name):
                    result = self.run_cli(
                        *command, "--config=missing.toml", f"--{name}=MIT"
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("invalid flag", result.stderr)

    def test_update_rejects_ignore_config_before_loading_files(self):
        for flags in (
            ["--ignore-config"],
            ["--ignore-config=true"],
            ["--ignore-config=false"],
            ["--ignore-config="],
            ["--ignore-config", "true"],
            ["--ignore-config", "false"],
        ):
            with self.subTest(flags=flags):
                result = self.run_cli("update", "--quiet", *flags)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("invalid flag 'ignore-config'", result.stderr)
                self.assertNotIn("Could not read", result.stderr)

    def test_update_terminal_preflight_precedes_invalid_target(self):
        target = self.project / "policy.toml"
        for original in (
            "name = [",
            "[tools.licence_audit]\nallow = true\n",
            "[[tools.licence_audit.exceptions]]\nreason = 'Missing finding'\n",
        ):
            with self.subTest(original=original):
                target.write_text(original)
                result = self.run_cli(
                    "update", "--config=policy.toml", "--quiet", "--no-cache"
                )
                self.assert_diagnostic(result)
                self.assertNotIn("manifest", result.stderr)
                self.assertEqual(
                    result.stderr,
                    "Error: The update picker requires an interactive terminal on stdin and stdout\n",
                )
                self.assertEqual(target.read_text(), original)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires named pipes")
    def test_update_terminal_preflight_does_not_read_config_or_manifest(self):
        for filename, flag in (
            ("blocked-policy.toml", "--config"),
            ("blocked-manifest.toml", "--manifest"),
        ):
            with self.subTest(filename=filename):
                os.mkfifo(self.project / filename)
                result = self.run_cli(
                    "update", f"{flag}={filename}", "--cache-dir=unused-cache"
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    "Error: The update picker requires an interactive terminal on stdin and stdout\n",
                )
                self.assertFalse((self.project / "unused-cache").exists())

    def test_update_terminal_preflight_prints_one_diagnostic_without_cache(self):
        (self.project / "manifest.toml").write_text(
            (ROOT / "test/fixtures/update_manifest.toml").read_text()
        )
        for verbosity in ([], ["--quiet"], ["--verbose"]):
            with self.subTest(verbosity=verbosity):
                result = self.run_cli(
                    "update", "--cache-dir=unused-cache", *verbosity,
                    environment={
                        "NO_COLOR": "1",
                        "HOME": str(self.project / "unused-home"),
                        "XDG_CACHE_HOME": str(self.project / "unused-xdg-cache"),
                    },
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    "Error: The update picker requires an interactive terminal on stdin and stdout\n",
                )
                for name in ("unused-cache", "unused-home", "unused-xdg-cache"):
                    self.assertFalse((self.project / name).exists())

    def test_update_missing_policy_reaches_terminal_requirement_without_writing(self):
        (self.project / "manifest.toml").write_text("packages = []\n")
        for target in (None, "policy.toml", "missing.toml"):
            with self.subTest(target=target):
                path = self.project / (target or "gleam.toml")
                if target != "missing.toml":
                    path.write_text("# Keep settings\nname = 'stream_fixture'\n")
                original = path.read_bytes() if path.exists() else None
                flags = [f"--config={target}"] if target else []
                result = self.run_cli("update", "--quiet", "--no-cache", *flags)
                self.assert_diagnostic(result)
                self.assertIn("interactive terminal", result.stderr)
                self.assertEqual(path.read_bytes() if path.exists() else None, original)

    def test_vulnerability_flags_require_scan_before_reading_manifest(self):
        for flags in (
            ["--vuln-severity=critical"],
            ["--vuln-block-unknown"],
            ["--vuln-block-unknown=false"],
            ["--vuln-severity=high", "--vuln-block-unknown"],
        ):
            for scan in ([], ["--checks=licences"]):
                with self.subTest(flags=flags, scan=scan):
                    result = self.run_cli("check", "--quiet", *flags, *scan)
                    self.assert_diagnostic(result)
                    self.assertIn("require --checks=vulns or --checks=all", result.stderr)
                    self.assertNotIn("manifest", result.stderr)

    def test_check_selection_usage_and_missing_policy_diagnostics(self):
        (self.project / "gleam.toml").write_text(
            'name = "stream_fixture"\nversion = "1.0.0"\n'
        )
        for flag in (
            "--checks=invalid", "--checks=", "--vulns",
            "--vulns=true", "--vulns=false",
        ):
            with self.subTest(flag=flag):
                result = self.run_cli("check", flag, "--quiet")
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("invalid flag", result.stderr)
        for selection in ("licences", "all"):
            result = self.run_cli("check", f"--checks={selection}", "--quiet")
            self.assert_diagnostic(result)
            self.assertIn("requires a non-empty allow list", result.stderr)
        result = self.run_cli("check", "--checks=vulns", "--quiet")
        self.assert_diagnostic(result)
        self.assertIn("manifest.toml", result.stderr)
        self.assertNotIn("allow list", result.stderr)

    def test_subcommand_help_and_version_streams(self):
        help_result = self.run_cli("check", "-h")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertEqual(help_result.stderr, "")
        self.assertIn("--quiet", help_result.stdout)
        self.assertIn("-q", help_result.stdout)
        version = self.run_cli("check", "--version")
        self.assertEqual(version.returncode, 2)
        self.assertEqual(version.stdout, "")
        self.assertIn("invalid flag", version.stderr)

    def test_vulns_removed_cache_flags_and_short_quiet(self):
        for flag in ("--no-cache", "--cache-dir=cache"):
            result = self.run_cli("vulns", flag)
            self.assertEqual(result.returncode, 2)
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

    def test_progress_color_mode_on_every_command(self):
        forced = ("always", {"NO_COLOR": "1", "TERM": "dumb"}, True)
        cases = (
            ("never", {"FORCE_COLOR": "1"}, False),
            forced,
            ("auto", {"NO_COLOR": "1", "FORCE_COLOR": "1"}, False),
            ("auto", {"FORCE_COLOR": "1"}, True),
            ("auto", {"TERM": "dumb"}, False),
        )
        for command in ("report", "check", "sbom", "vulns", "notices", "update"):
            command_cases = cases if command == "report" else (forced,)
            for mode, environment, colored in command_cases:
                with self.subTest(command=command, mode=mode, env=environment):
                    result = self.run_cli(
                        command, "--verbose", f"--color={mode}",
                        environment=environment,
                    )
                    self.assert_diagnostic(result)
                    lines = result.stderr.splitlines()
                    progress = [line for line in lines if " | " in line]
                    if command == "update":
                        self.assertEqual(
                            result.stderr,
                            "Error: The update picker requires an interactive terminal on stdin and stdout\n",
                        )
                        self.assertEqual(progress, [])
                    else:
                        self.assertTrue(progress, result.stderr)
                        for line in progress:
                            self.assertEqual("\x1b[" in line, colored, line)

    def test_deferred_diagnostics_respect_color_mode(self):
        (self.project / "manifest.toml").write_text("packages = []\n")
        blocker = self.project / "cache"
        blocker.write_text("not a directory")
        for command in ("check", "sbom"):
            for mode, environment, colored in (
                ("never", {"FORCE_COLOR": "1"}, False),
                ("always", {"NO_COLOR": "1"}, True),
                ("auto", {"NO_COLOR": "1"}, False),
            ):
                with self.subTest(command=command, mode=mode):
                    arguments = (
                        [] if command == "check"
                        else ["--offline", "--reproducible"]
                    )
                    result = self.run_cli(
                        command, *arguments, f"--color={mode}",
                        environment={
                            **environment, "XDG_CACHE_HOME": str(blocker),
                        },
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    warning = next(
                        line for line in result.stderr.splitlines()
                        if "Unable to open licence cache" in line
                    )
                    self.assertEqual("\x1b[" in warning, colored, warning)
                    self.assertEqual("\x1b[" in result.stdout, False)
                    if command == "sbom":
                        self.assertEqual(
                            json.loads(result.stdout)["bomFormat"], "CycloneDX"
                        )
                    if command == "check":
                        success = next(
                            line for line in result.stderr.splitlines()
                            if "Licence audit completed" in line
                        )
                        self.assertEqual("\x1b[" in success, colored, success)

    @unittest.skipUnless(hasattr(os, "openpty"), "requires POSIX terminals")
    def test_auto_detects_stderr_independently_of_stdout(self):
        (self.project / "manifest.toml").write_text("packages = []\n")
        blocker = self.project / "cache"
        blocker.write_text("not a directory")
        env = dict(os.environ)
        for name in ("NO_COLOR", "FORCE_COLOR", "CI", "COLORTERM"):
            env.pop(name, None)
        env.update(TERM="xterm-256color", XDG_CACHE_HOME=str(blocker))
        for mode, colored in (("auto", True), ("never", False)):
            with self.subTest(mode=mode):
                master, slave = os.openpty()
                try:
                    result = subprocess.run(
                        [
                            str(ROOT / "licence_audit"), "check",
                            f"--color={mode}",
                        ],
                        cwd=self.project, stdout=subprocess.PIPE, stderr=slave,
                        text=True, env=env, timeout=30,
                    )
                    os.set_blocking(master, False)
                    stderr = os.read(master, 65536).decode()
                finally:
                    os.close(slave)
                    os.close(master)
                self.assertEqual(result.returncode, 0, stderr)
                self.assertNotIn("\x1b[", result.stdout)
                self.assertIn("Unable to open licence cache", stderr)
                self.assertEqual("\x1b[" in stderr, colored, stderr)

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
        result = self.run_cli("notices", "--quiet", f"--cache-dir={cache_path}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Third-party licences", result.stdout)
        self.assertNotIn("Products using this licence", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertFalse(cache_path.exists())

        (self.project / "local").mkdir()
        (self.project / "local/LICENSE").write_text("Local dev licence\n")
        result = self.run_cli("notices", "--scope=all", "--quiet", "--no-cache")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("local 1.0.0", result.stdout)
        self.assertIn("Local dev licence", result.stdout)
        self.assertEqual(result.stderr, "")

        (self.project / "gleam.toml").write_text(
            project_config + 'exclude = ["stale"]\n'
        )
        result = self.run_cli("notices", "--quiet", f"--cache-dir={cache_path}")
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

    def test_sbom_license_text_uses_only_explicit_application_root(self):
        (self.project / "manifest.toml").write_text(
            'packages = [{ name = "example", version = "1.0.0", '
            f'source = "hex", outer_checksum = "{HEX_CHECKSUM}" }}]\n'
            '[requirements]\nexample = "1.0.0"\n'
        )
        cache_root = self.project / "cache-é中"
        metadata_path = cache_root / "hex-v2"
        cache_home = self.project / "cache"
        home = self.project / "unused-home"
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
                        "--quiet",
                        *(["--no-cache"] if mode == "no_cache"
                          else [f"--cache-dir={cache_root}"]),
                    ],
                    cwd=self.project, capture_output=True, text=True, timeout=30,
                    env={
                        **os.environ, "NO_COLOR": "1",
                        "XDG_CACHE_HOME": str(cache_home), "HOME": str(home),
                        "SBOM_CACHE_MODE": mode,
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
                notice_files = list(cache_root.glob("spdx-v1/*.json"))
                self.assertEqual(len(notice_files), 1)
                entry = json.loads(notice_files[0].read_text())
                self.assertTrue(entry["key"].startswith("spdx:"))
                self.assertTrue(entry["key"].endswith(":license:Apache-2.0"))
                self.assertEqual(entry["value"], "Cached SPDX text")
                self.assertFalse(cache_home.exists())
                self.assertFalse(home.exists())
                self.assertFalse(list(cache_root.rglob("*.tmp")))
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
            f'otp_app = "example", source = "hex", outer_checksum = "{HEX_CHECKSUM}" }}]\n'
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
                Checksum = list_to_binary(os:getenv("STREAM_ARCHIVE_CHECKSUM")),
                {{ok, _}, none} = 'licence_audit@cache':fetch_immutable(
                    Cache, <<"example@1.0.0@hex:", Checksum/binary>>,
                    fun() ->
                        'licence_audit@notice':hex_metadata_from_locked_source(
                            <<"example">>, <<"1.0.0">>, Checksum,
                            fun(_, _) -> file:read_file(os:getenv("STREAM_ARCHIVE_PATH")) end)
                    end),
                none = 'licence_audit@cache':close(Cache),
                halt(0).
                """,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ, "STREAM_CACHE_PATH": str(cache_path),
                "STREAM_ARCHIVE_PATH": str(HEX_ARCHIVE),
                "STREAM_ARCHIVE_CHECKSUM": HEX_CHECKSUM,
            },
        )
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        for licence, status in (("MIT", 1), ("Apache-2.0", 0)):
            policy = self.project / "gate-policy.toml"
            policy.write_text(
                f'[tools.licence_audit]\nallow = ["{licence}"]\n'
            )
            for quiet in (False, True):
                with self.subTest(licence=licence, quiet=quiet):
                    result = self.run_cli(
                        "check", f"--config={policy}",
                        f"--cache-dir={cache_path}",
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
            f'otp_app = "example", source = "hex", outer_checksum = "{HEX_CHECKSUM}" }}]\n'
            '[requirements]\nexample = ">= 1.0.0"\n'
        )
        # Precompile only fetch replacements; keep real formatting and stream dispatch.
        evaluation = """
            {ok, Archive} = file:read_file(os:getenv("STREAM_ARCHIVE_PATH")),
            SourceResult = case os:getenv("STREAM_CHECK_SELECTION") of
                "vulns" -> {error, fetch_network_failure};
                _ -> {ok, Archive}
            end,
            Notice = 'licence_audit@notice',
            {ok, {Notice, [{abstract_code, {raw_abstract_v1, NoticeForms}}]}} =
                beam_lib:chunks(code:which(Notice), [abstract_code]),
            SourceForms = lists:map(fun
                ({function, Line, fetch_hex_tarball_from_hex, 2, _}) ->
                    {function, Line, fetch_hex_tarball_from_hex, 2, [
                        {clause, Line, [{var, Line, '_'}, {var, Line, '_'}], [],
                            [erl_parse:abstract(SourceResult)]}
                    ]};
                (Form) -> Form
            end, NoticeForms),
            {ok, Notice, NoticeBinary} = compile:forms(SourceForms, [binary]),
            Directory = os:getenv("STREAM_FIXTURE_EBIN"),
            ok = file:write_file(
                filename:join(Directory, atom_to_list(Notice) ++ ".beam"), NoticeBinary),
            Mode = os:getenv("STREAM_OSV_MODE"),
            Severity = case Mode of "unknown" -> unknown_severity; _ -> high end,
            Batch = case Mode of
                "batch_failure" -> {error, {network_failure, <<"fixture connection failed">>}};
                _ -> {ok, [{batch_entry, <<"pkg:hex/example@1.0.0">>,
                    [<<"CVE-STREAM-0001">>]}]}
            end,
            Detail = case Mode of
                "detail_failure" -> {error, not_found};
                _ -> {ok, {vulnerability, <<"CVE-STREAM-0001">>, [],
                    <<"Fixture advisory">>, Severity, [], []}}
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
            ok = file:write_file(
                filename:join(Directory, atom_to_list(Osv) ++ ".beam"), OsvBinary),
            halt(0).
        """
        cases = (
            (mode, deny, status, selection)
            for selection in ("all", "vulns")
            for mode, deny, status in (
                ("high", False, 1),
                ("unknown", False, 1),
                ("batch_failure", False, 2),
                ("detail_failure", False, 2),
                ("batch_failure", True, 2),
                ("detail_failure", True, 2),
            )
        )
        fixtures = {}
        for mode, deny_licence, status, selection in cases:
            key = (mode, selection)
            if key not in fixtures:
                fixtures[key] = self.compile_fixture(
                    evaluation,
                    {
                        "STREAM_OSV_MODE": mode,
                        "STREAM_CHECK_SELECTION": selection,
                        "STREAM_ARCHIVE_PATH": str(HEX_ARCHIVE),
                    },
                )
            for quiet in (False, True):
                with self.subTest(
                    mode=mode, deny_licence=deny_licence, quiet=quiet,
                    selection=selection,
                ):
                    policy = self.project / "vulnerability-policy.toml"
                    policy.write_text(
                        '[tools.licence_audit]\nallow = ["Apache-2.0"]\n'
                        + ('deny = ["Apache-2.0"]\n' if deny_licence else '')
                    )
                    cache_path = self.project / "vulnerability-only-cache"
                    arguments = [
                        "check", f"--checks={selection}", f"--config={policy}"
                    ]
                    if selection == "all":
                        arguments += ["--no-cache"]
                    else:
                        arguments += [f"--cache-dir={cache_path}"]
                    if mode == "unknown":
                        arguments += ["--vuln-block-unknown"]
                    if quiet:
                        arguments += ["--quiet"]
                    result = self.run_cli(*arguments, fixture=fixtures[key])
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                    if selection == "all" or status == 1:
                        self.assertIn("example", result.stdout)
                    else:
                        self.assertEqual(result.stdout, "")
                    if selection == "vulns":
                        self.assertNotIn("Licence audit", result.stderr)
                        self.assertNotIn("unexpected licence fetch", result.stdout)
                        self.assertFalse(cache_path.exists())
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
        for arguments in (["report"], ["check"], ["sbom", "--offline"]):
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
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr)

    def test_incomplete_reports_exit_two_on_stdout(self):
        policy = self.project / "archive-policy.toml"
        policy.write_text('[tools.licence_audit]\nallow = ["Apache-2.0"]\n')
        packages = [
            '{ name = "' + name + '", version = "1.0.0", '
            'build_tools = ["gleam"], requirements = [], '
            'otp_app = "' + name + '", source = "hex", outer_checksum = "' + HEX_CHECKSUM + '" }'
            for name in ("healthy", "unavailable")
        ]
        (self.project / "manifest.toml").write_text(
            "packages = [" + ", ".join(packages) + "]\n"
            '[requirements]\nhealthy = ">= 1.0.0"\nunavailable = ">= 1.0.0"\n'
        )
        # All cases share an immutable fetch fixture, but run in separate VMs.
        evaluation = """
            {ok, Archive} = file:read_file(os:getenv("STREAM_ARCHIVE_PATH")),
            Module = 'licence_audit@notice',
            {ok, {Module, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
                beam_lib:chunks(code:which(Module), [abstract_code]),
            Replaced = lists:map(fun
                ({function, Line, fetch_hex_tarball_from_hex, 2, _}) ->
                    {function, Line, fetch_hex_tarball_from_hex, 2, [
                        {clause, Line, [erl_parse:abstract(<<"healthy">>), {var, Line, '_'}], [],
                            [erl_parse:abstract({ok, Archive})]},
                        {clause, Line, [{var, Line, '_'}, {var, Line, '_'}], [],
                            [erl_parse:abstract({error, fetch_timeout})]}
                    ]};
                (Form) -> Form
            end, Forms),
            {ok, Module, Binary} = compile:forms(Replaced, [binary]),
            ok = file:write_file(
                filename:join(os:getenv("STREAM_FIXTURE_EBIN"),
                    atom_to_list(Module) ++ ".beam"), Binary),
            halt(0).
        """
        fixture = self.compile_fixture(
            evaluation, {"STREAM_ARCHIVE_PATH": str(HEX_ARCHIVE)}
        )
        for command, mode, environment, colored in (
            (command, mode, environment, colored)
            for command in ([], ["report"], ["check", f"--config={policy}"])
            for mode, environment, colored in (
                ("never", {"FORCE_COLOR": "1"}, False),
                ("always", {"NO_COLOR": "1"}, True),
                ("auto", {"NO_COLOR": "1"}, False),
            )
        ):
            with self.subTest(command=command, mode=mode):
                result = self.run_cli(
                    *command, "--no-cache", f"--color={mode}",
                    environment=environment, fixture=fixture,
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("healthy", result.stdout)
                self.assertIn("Apache-2.0", result.stdout)
                self.assertIn("unavailable", result.stdout)
                self.assertIn("timed out after 30s", result.stdout)
                self.assertIn("package metadata could not be fetched", result.stderr)
                self.assertNotIn("healthy", result.stderr)
                for message in (
                    "Failed to fetch package metadata",
                    "package metadata could not be fetched",
                ):
                    line = next(
                        line for line in result.stderr.splitlines()
                        if message in line
                    )
                    self.assertEqual("\x1b[" in line, colored, line)

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
            f'otp_app = "gleam_stdlib", source = "hex", outer_checksum = "{HEX_CHECKSUM}" }}]\n'
            '[requirements]\ngleam_stdlib = ">= 0.60.0"\n'
        )
        for arguments in (["check", "--no-cache"], ["vulns"]):
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
                        "ERL_FLAGS": "+S 2:2 +SDcpu 1 +SDio 1 -public_key cacerts_path [47,110,111]",
                    },
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                certificate_error = (
                    ("FailedLoadCacerts", "Enoent")
                    if arguments[0] == "check"
                    else ("failed_load_cacerts", "enoent")
                )
                for detail in certificate_error:
                    self.assertIn(detail, result.stderr)
                self.assertNotIn("runtime error:", result.stderr.lower())
                self.assertNotIn("stack trace", result.stderr.lower())
                self.assertNotIn("runtime terminating", result.stderr.lower())
                self.assertFalse((self.project / "erl_crash.dump").exists())


if __name__ == "__main__":
    unittest.main()
