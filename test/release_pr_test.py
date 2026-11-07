import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_pr", ROOT / "scripts/release_pr.py"
)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
RUN = subprocess.run


class ReleasePrTest(unittest.TestCase):
    def setUp(self):
        self.previous = Path.cwd()
        (ROOT / "build").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="release-pr-", dir=ROOT / "build")
        os.chdir(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.chdir, self.previous)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.pending = []
        self.prepared = []

    def git(self, *args):
        return RUN(
            ["git", *args], check=True, capture_output=True, text=True,
        ).stdout.strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def manifest(self, version):
        Path("gleam.toml").write_text(
            f'name = "licence_audit"\nversion = "{version}"\n'
            'licences = ["Apache-2.0"]\n\n[tools.trellis]\n'
        )

    def fragment(self, name="initial", body="Initial fix"):
        directory = Path(".changes/unreleased")
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{name}.toml").write_text(
            f'package = "licence_audit"\nkind = "Fixed"\nbody = "{body}"\n'
        )

    def candidate(self, version="1.0.0-rc.0"):
        self.manifest(version)
        self.fragment()
        return self.commit("Release candidate")

    def open_pr(self, version):
        self.git("switch", "-qc", "release/pending")
        self.manifest(version)
        sha = self.commit("Pending release")
        self.git("switch", "-q", "main")
        self.pending = [{"headRefOid": sha, "isCrossRepository": False}]

    def prepare(self, event="push", pre="", version=""):
        def run(args, **kwargs):
            if args[0] == "gh":
                return subprocess.CompletedProcess(args, 0, json.dumps(self.pending))
            if args[:3] == ["trellis", "release", "pr"]:
                self.prepared.append(args)
                # Exercise pinned Trellis's real version and fragment semantics,
                # without pushing a branch or calling the GitHub API.
                return RUN(["trellis", "version", "apply", *args[7:]],
                           check=True, capture_output=True, text=True)
            return RUN(args, **kwargs)

        with mock.patch.object(release.subprocess, "run", side_effect=run):
            return release.prepare(event, pre, version)

    def assert_version(self, expected, retained=True):
        self.assertEqual(tomllib.loads(Path("gleam.toml").read_text())["version"], expected)
        self.assertEqual(Path(".changes/unreleased/initial.toml").exists(), retained)

    def test_stable_push_prepares_stable_release(self):
        self.candidate("0.15.0")
        self.assertTrue(self.prepare())
        self.assert_version("0.15.1", retained=False)

    def test_new_fragment_prepares_next_candidate(self):
        self.candidate()
        self.fragment("new", "New fix")
        self.commit("New change")
        self.assertTrue(self.prepare())
        self.assert_version("1.0.0-rc.1")
        self.assertTrue(Path(".changes/unreleased/new.toml").exists())

    def test_changed_fragment_prepares_next_candidate(self):
        self.candidate()
        self.fragment(body="Corrected fix")
        self.commit("Correct fragment")
        self.assertTrue(self.prepare())
        self.assert_version("1.0.0-rc.1")

    def test_candidate_merge_and_unrelated_push_do_not_loop(self):
        baseline = self.candidate()
        self.assertFalse(self.prepare())
        Path("README.md").write_text("Docs change\n")
        self.commit("Docs only")
        self.manifest("1.0.0-rc.0")
        with Path("gleam.toml").open("a") as manifest:
            manifest.write('\n[dependencies]\ngleam_stdlib = ">= 1.0.0"\n')
        self.commit("Dependency change without a fragment")
        self.assertFalse(self.prepare())
        self.assertEqual(release.git_stdout(
            "log", "-1", "--format=%H", "-G", "^version[[:space:]]*=", "--", "gleam.toml",
        ), baseline)
        self.assertEqual(self.prepared, [])

    def test_pending_candidate_keeps_number(self):
        self.candidate()
        self.open_pr("1.0.0-rc.1")
        self.fragment("new")
        self.commit("New change")
        self.assertTrue(self.prepare())
        self.assert_version("1.0.0-rc.1")

    def test_pending_candidate_entry_keeps_target(self):
        self.candidate("0.15.0")
        self.open_pr("1.0.0-rc.0")
        self.fragment("new")
        self.commit("New change")
        self.assertTrue(self.prepare())
        self.assert_version("1.0.0-rc.0")

    def test_pending_candidate_retarget_keeps_target(self):
        self.candidate()
        self.open_pr("2.0.0-rc.0")
        self.assertTrue(self.prepare())
        self.assert_version("2.0.0-rc.0")

    def test_pending_promotion_stays_stable(self):
        self.candidate()
        self.open_pr("1.0.0")
        self.fragment("new")
        self.commit("New change")
        self.assertTrue(self.prepare())
        self.assert_version("1.0.0", retained=False)

    def test_pending_stable_keeps_target(self):
        self.candidate("1.0.0")
        self.open_pr("1.1.0")
        self.assertTrue(self.prepare())
        self.assert_version("1.1.0", retained=False)

    def test_closed_candidate_branch_does_not_set_mode(self):
        self.candidate("1.0.0")
        self.open_pr("2.0.0-rc.0")
        self.pending = []
        self.assertTrue(self.prepare())
        self.assert_version("1.0.1", retained=False)

    def test_fork_release_branch_does_not_set_mode(self):
        self.candidate("1.0.0")
        self.pending = [{"headRefOid": "not-local", "isCrossRepository": True}]
        self.assertTrue(self.prepare())
        self.assert_version("1.0.1", retained=False)

    def test_next_candidate_merge_does_not_loop(self):
        self.candidate()
        self.fragment("new")
        self.commit("New change")
        self.assertTrue(self.prepare())
        self.assert_version("1.0.0-rc.1")
        self.commit("Release next candidate")
        self.assertFalse(self.prepare())

    def test_manual_entry_and_promotion_override_pending(self):
        self.candidate("0.15.0")
        self.open_pr("0.15.1")
        self.assertTrue(self.prepare("workflow_dispatch", "rc", "1.0.0"))
        self.assert_version("1.0.0-rc.0")
        self.commit("Enter candidate mode")
        self.assertTrue(self.prepare("workflow_dispatch", "none"))
        self.assert_version("1.0.0", retained=False)
        self.commit("Promote candidate")
        self.pending = []
        self.fragment("stable")
        self.commit("Stable fix")
        self.assertTrue(self.prepare())
        self.assert_version("1.0.1", retained=False)

    def test_github_failure_is_not_treated_as_no_pending_pr(self):
        self.candidate()
        with mock.patch.object(release.subprocess, "run",
                               side_effect=subprocess.CalledProcessError(1, ["gh"])):
            with self.assertRaises(subprocess.CalledProcessError):
                release.prepare("push")

    def test_git_diff_failure_is_not_treated_as_no_changes(self):
        self.candidate()
        with mock.patch.object(release, "git_stdout", return_value="missing"), \
                mock.patch.object(release.subprocess, "run", return_value=
                                  subprocess.CompletedProcess(["git", "diff"], 128)):
            with self.assertRaises(subprocess.CalledProcessError):
                release.new_candidate_changes()


if __name__ == "__main__":
    unittest.main()
