import os
from pathlib import Path
import shutil
import sys
import unittest
import uuid

from native_release_smoke import interactive, validate_output


class NativeReleaseSmokeTest(unittest.TestCase):
    def test_runtime_errors_and_incomplete_reports_fail_even_with_exit_zero(self):
        for output in (
            "noproc", "Runtime terminating", "Vulnerability check incomplete:",
            "(details unavailable)", "Picker failed to read terminal input",
            "WARN  | report | Cache unavailable; continuing without cache",
        ):
            with self.subTest(output=output), self.assertRaises(AssertionError):
                validate_output("report", output, 0)

    def test_only_an_explicit_advisory_gate_may_exit_one(self):
        validate_output(
            "check", "Vulnerability check failed: one or more advisories", 1,
        )
        with self.assertRaises(AssertionError):
            validate_output("check", "HTTP request failed", 1)
        with self.assertRaises(AssertionError):
            validate_output("report", "Vulnerability check failed: one or more advisories", 1)

    def test_ipv6_fallback_does_not_hide_other_warnings(self):
        fallback = (
            "WARN  | report | IPv6 probe timed out after 1000ms; "
            "using IPv4 for the remaining Hex and OSV requests"
        )
        validate_output("report", fallback, 0)
        with self.assertRaises(AssertionError):
            validate_output("report", fallback + "\nWARN  | report | Cache unavailable", 0)

    def test_expected_terminal_warnings_do_not_hide_runtime_failures(self):
        output = (
            "WARN  | update | The update picker requires an interactive terminal "
            "on stdin and stdout"
        )
        validate_output("update-redirected", output, 1, expected=1)
        validate_output("update-cancel", "WARN  | update | Update cancelled", 130, expected=130)
        with self.assertRaises(AssertionError):
            validate_output("update-redirected", output + "\nnoproc", 1, expected=1)

    @unittest.skipIf(os.name == "nt", "Unix PTY driver; ConPTY is tested on the release host")
    def test_interactive_driver_supplies_a_real_terminal_and_keyboard_input(self):
        work = (Path("build") / f"native-smoke-test-{uuid.uuid4().hex}").resolve()
        work.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, work)
        binary = work / "picker"
        binary.write_text(
            f"#!{sys.executable}\n"
            "import os, sys, tty\n"
            "assert os.isatty(0) and os.isatty(1)\n"
            "tty.setraw(0)\n"
            "print('esc cancel', flush=True)\n"
            "assert os.read(0, 2) == b'd\\r'\n"
            "print('saved', flush=True)\n",
        )
        binary.chmod(0o755)
        output, status = interactive(binary, work, dict(os.environ), "d\r")
        self.assertEqual(status, 0)
        self.assertIn("saved", output)


if __name__ == "__main__":
    unittest.main()
