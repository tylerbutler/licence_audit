from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from publish_release import publish


class PublishReleaseTest(unittest.TestCase):
    def arguments(self):
        directory = Mock()
        asset = Mock()
        asset.is_file.return_value = True
        asset.__str__ = Mock(return_value="dist/archive.tar.gz")
        directory.iterdir.return_value = [asset]
        template = Mock()
        template.read_text.return_value = "<!-- install-instructions --> ${REPO} ${REF_NAME}"
        changelog = Mock()
        changelog.read_text.return_value = "## v1.0.0 - 2026-10-24\n\n### Fixed\n\n- Fix.\n\n## v0.9.0 - earlier\nOld."
        return "v1.0.0", "owner/repo", directory, template, changelog

    @patch("publish_release.subprocess.run")
    def test_failed_cancelled_or_skipped_required_target_never_creates_a_release(self, run):
        for result in ("failure", "cancelled", "skipped", ""):
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                publish(*self.arguments(), "success", result)
        run.assert_not_called()

    @patch("publish_release.subprocess.run")
    def test_new_release_stays_draft_until_upload_and_notes_succeed(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, "")
        run.side_effect = [
            subprocess.CompletedProcess([], 1, ""),
            subprocess.CompletedProcess([], 0, ""),
            subprocess.CalledProcessError(1, "gh release upload"),
        ]
        with self.assertRaises(subprocess.CalledProcessError):
            publish(*self.arguments(), "success", "success")
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn("--draft", calls[1])
        self.assertNotIn("--draft=false", str(calls))

    @patch("publish_release.subprocess.run")
    def test_success_publishes_last_with_matching_changelog(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 1, ""),
            *[subprocess.CompletedProcess([], 0, "") for _ in range(4)],
        ]
        publish(*self.arguments(), "success", "success")
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(calls[-1], ["gh", "release", "edit", "v1.0.0", "--draft=false"])
        self.assertEqual(calls[1][-1], "### Fixed\n\n- Fix.")
        self.assertIn("owner/repo v1.0.0", calls[-2][-1])


if __name__ == "__main__":
    unittest.main()
