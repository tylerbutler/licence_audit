import importlib.util
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_pr", ROOT / "scripts/release_pr.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
COMMAND = ["trellis", "release", "pr", "--base", "main", "--branch", "release/pending"]


class ReleasePrTest(unittest.TestCase):
    def test_manual_candidates_and_promotion(self):
        for pre, version, flags in [
            ("rc", "1.0.0", ["--pre", "rc", "--set", "licence_audit=1.0.0"]),
            ("rc", "", ["--pre", "rc"]),
            ("none", "", ["--pre", "none"]),
            ("", "", []),
            (" rc ", " 1.0.0 ", ["--pre", "rc", "--set", "licence_audit=1.0.0"]),
        ]:
            with self.subTest(pre=pre, version=version), mock.patch.object(
                release.subprocess, "run"
            ) as run:
                self.assertTrue(release.prepare("workflow_dispatch", pre, version))
                run.assert_called_once_with(COMMAND + flags, check=True)

    def test_automatic_push_leaves_prerelease_main_unchanged(self):
        with mock.patch.object(Path, "read_text", return_value='version = "1.0.0-rc.0"'), \
             mock.patch.object(release.subprocess, "run") as run:
            self.assertFalse(release.prepare("push"))
            run.assert_not_called()

    def test_automatic_push_checks_pending_release(self):
        for pending_version, prepared in [("1.0.0-rc.0", False), ("0.15.0", True)]:
            with self.subTest(version=pending_version), \
                 mock.patch.object(Path, "read_text", return_value='version = "0.14.0"'), \
                 mock.patch.object(release.subprocess, "run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 0, f'version = "{pending_version}"'),
                    subprocess.CompletedProcess([], 0),
                ]
                self.assertEqual(release.prepare("push"), prepared)
                self.assertEqual(run.call_count, 3 if prepared else 2)
                if prepared:
                    self.assertEqual(run.call_args, mock.call(COMMAND, check=True))

    def test_automatic_push_without_pending_branch(self):
        with mock.patch.object(Path, "read_text", return_value='version = "0.14.0"'), \
             mock.patch.object(release.subprocess, "run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 1),
                subprocess.CompletedProcess([], 0),
            ]
            self.assertTrue(release.prepare("push"))
            self.assertEqual(run.call_args, mock.call(COMMAND, check=True))

    def test_failures_stop_preparation(self):
        with mock.patch.object(Path, "read_text", return_value='version = "0.14.0"'), \
             mock.patch.object(release.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 128)
            with self.assertRaises(subprocess.CalledProcessError):
                release.prepare("push")
            run.assert_called_once()
        with mock.patch.object(release.subprocess, "run") as run:
            run.side_effect = subprocess.CalledProcessError(1, COMMAND)
            with self.assertRaises(subprocess.CalledProcessError):
                release.prepare("workflow_dispatch", "rc", "1.0.0")

    def test_build_metadata_is_not_a_prerelease(self):
        self.assertFalse(release.is_prerelease('version = "1.0.0+build-123"'))

    def test_workflow_output_and_main_branch_requirement(self):
        with tempfile.TemporaryDirectory() as work:
            output = Path(work) / "output"
            env = {
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_OUTPUT": str(output),
                "INPUT_PRE": "rc",
                "INPUT_VERSION": "1.0.0",
            }
            with mock.patch.dict(os.environ, env), mock.patch.object(
                subprocess, "run"
            ) as run:
                runpy.run_path(str(SPEC.origin), run_name="__main__")
                run.assert_called_once_with(
                    COMMAND + ["--pre", "rc", "--set", "licence_audit=1.0.0"], check=True
                )
                self.assertEqual(output.read_text(), "prepared=true\n")
            output.unlink()
            env["GITHUB_REF"] = "refs/heads/feature"
            with mock.patch.dict(os.environ, env), mock.patch.object(
                subprocess, "run"
            ) as run:
                with self.assertRaisesRegex(SystemExit, "Run release preparation on main"):
                    runpy.run_path(str(SPEC.origin), run_name="__main__")
                run.assert_not_called()
                self.assertFalse(output.exists())

    def test_skipped_workflow_does_not_refresh_artifacts(self):
        with tempfile.TemporaryDirectory() as work:
            output = Path(work) / "output"
            env = {
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_OUTPUT": str(output),
            }
            with mock.patch.dict(os.environ, env), \
                 mock.patch.object(Path, "read_text", return_value='version = "1.0.0-rc.0"'), \
                 mock.patch.object(subprocess, "run") as run:
                runpy.run_path(str(SPEC.origin), run_name="__main__")
                run.assert_not_called()
            self.assertEqual(output.read_text(), "prepared=false\n")
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("if: steps.prepare.outputs.prepared == 'true'", workflow)

    def test_pinned_trellis_candidate_lifecycle(self):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            shutil.copy2(ROOT / "gleam.toml", work)
            shutil.copytree(ROOT / ".changes", work / ".changes")
            shutil.copy2(ROOT / "CHANGELOG.md", work)
            for source in [ROOT / "test/fixtures", ROOT / "vendor"]:
                for manifest in source.rglob("gleam.toml"):
                    target = work / manifest.relative_to(ROOT)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(manifest, target)
            subprocess.run(
                ["git", "init", "--quiet", str(work)], check=True, capture_output=True
            )
            fragments = {
                path.name: path.read_bytes()
                for path in (work / ".changes/unreleased").glob("*.toml")
            }
            self.assertTrue(fragments)
            for flags, version, retained in [
                (["--set", "licence_audit=1.0.0", "--pre", "rc"], "1.0.0-rc.0", True),
                (["--pre", "rc"], "1.0.0-rc.1", True),
                (["--pre", "none"], "1.0.0", False),
            ]:
                with self.subTest(version=version):
                    result = subprocess.run(
                        ["trellis", "version", "apply", "-C", str(work), "--json"] + flags,
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    applied = json.loads(result.stdout)
                    self.assertEqual(applied["bumped"][0]["next"], version)
                    self.assertEqual(applied["fragments_retained"], retained)
                    self.assertEqual(
                        tomllib.loads((work / "gleam.toml").read_text())["version"], version
                    )
                    remaining = {
                        path.name: path.read_bytes()
                        for path in (work / ".changes/unreleased").glob("*.toml")
                    }
                    self.assertEqual(remaining, fragments if retained else {})
                    self.assertIn(version, (work / "CHANGELOG.md").read_text())
