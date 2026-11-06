import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hex_publish", ROOT / "scripts/hex_publish.py")
hex_publish = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hex_publish)


class HexPublishTest(unittest.TestCase):
    def test_eligible_versions(self):
        for version in ["1.0.0", "1.0.0-rc.0", "1.0.0-rc.12", "1.1.0", "2.0.0-rc.1"]:
            with self.subTest(version=version):
                self.assertTrue(hex_publish.eligible(f"v{version}", version))
        for version in ["0.14.0", "0.99.0-rc.0", "1.0.0-alpha.0", "1.0.0-beta.1",
                        "1.0.0-rc", "1.0.0-rc.01", "01.0.0", "1.0.0+build", "1.0"]:
            with self.subTest(version=version):
                self.assertFalse(hex_publish.eligible(f"v{version}", version))

    def test_tag_must_match_package(self):
        for tag in ["v1.0.1", "1.0.0", "refs/heads/main", "v1.0.0\n"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                hex_publish.eligible(tag, "1.0.0")

    def test_hex_lookup(self):
        response = io.BytesIO(json.dumps({"version": "1.0.0-rc.0"}).encode())
        with patch.object(hex_publish, "urlopen", return_value=response) as request:
            self.assertTrue(hex_publish.release_exists("1.0.0-rc.0"))
            request.assert_called_once_with(
                "https://hex.pm/api/packages/licence_audit/releases/1.0.0-rc.0", timeout=30)
        for code in [404, 401, 429, 500]:
            error = HTTPError("url", code, "error", None, None)
            with patch.object(hex_publish, "urlopen", side_effect=error):
                if code == 404:
                    self.assertFalse(hex_publish.release_exists("1.0.0"))
                else:
                    with self.assertRaises(HTTPError):
                        hex_publish.release_exists("1.0.0")
        with patch.object(hex_publish, "urlopen", side_effect=URLError("offline")):
            with self.assertRaises(URLError):
                hex_publish.release_exists("1.0.0")
        with patch.object(hex_publish, "urlopen", return_value=io.BytesIO(b'{"version":"0.1.0"}')):
            with self.assertRaises(ValueError):
                hex_publish.release_exists("1.0.0")

    def test_publication_and_retries(self):
        manifest = b'name = "licence_audit"\nversion = "1.0.0"\n'
        with patch.object(Path, "read_text", return_value=manifest.decode()), \
                patch.object(hex_publish, "release_exists") as exists, \
                patch.object(hex_publish, "check_package") as check, \
                patch.object(hex_publish.subprocess, "run") as run:
            with patch.dict(os.environ, {}, clear=True):
                exists.return_value = True
                hex_publish.publish("v1.0.0")
                run.assert_not_called()
                check.assert_not_called()
                exists.return_value = False
                with self.assertRaisesRegex(ValueError, "HEXPM_API_KEY"):
                    hex_publish.publish("v1.0.0")
                run.assert_not_called()
            with patch.dict(os.environ, {"HEXPM_API_KEY": "test-only"}):
                hex_publish.publish("v1.0.0")
                self.assertEqual([call.args[0] for call in run.call_args_list],
                                 [["gleam", "export", "hex-tarball"],
                                  ["gleam", "publish", "--yes"]])
                check.assert_called_once_with(Path.cwd())
                run.reset_mock()
                check.side_effect = ValueError("bad package")
                with self.assertRaises(ValueError):
                    hex_publish.publish("v1.0.0")
                run.assert_called_once_with(["gleam", "export", "hex-tarball"], check=True)

    def test_command_failures_stop_publication(self):
        with patch.object(Path, "read_text", return_value='name = "licence_audit"\nversion = "1.0.0-rc.0"'), \
                patch.object(hex_publish, "release_exists", return_value=False), \
                patch.object(hex_publish, "check_package"), \
                patch.dict(os.environ, {"HEXPM_API_KEY": "test-only"}), \
                patch.object(hex_publish.subprocess, "run") as run:
            error = subprocess.CalledProcessError(1, "gleam")
            run.side_effect = error
            with self.assertRaises(subprocess.CalledProcessError):
                hex_publish.publish("v1.0.0-rc.0")
            self.assertEqual(run.call_count, 1)
            run.reset_mock()
            run.side_effect = [None, error]
            with self.assertRaises(subprocess.CalledProcessError):
                hex_publish.publish("v1.0.0-rc.0")
            self.assertEqual(run.call_count, 2)

    def test_ineligible_release_does_not_contact_hex(self):
        with patch.object(Path, "read_text", return_value='name = "licence_audit"\nversion = "0.14.0"'), \
                patch.object(hex_publish, "release_exists") as exists:
            hex_publish.publish("v0.14.0")
            exists.assert_not_called()
            with self.assertRaises(ValueError):
                hex_publish.publish("v1.0.0")
            exists.assert_not_called()

    def test_package_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build").mkdir()
            (root / "src").mkdir()
            files = {"gleam.toml": b'version = "1.0.0"\n', "README.md": b"readme",
                     "LICENSE": b"licence", "NOTICE": b"vendored notices",
                     "src/main.gleam": b"source", "src/main_ffi.erl": b"native"}
            for name, content in files.items():
                (root / name).write_bytes(content)

            def archive(inputs):
                contents = io.BytesIO()
                with tarfile.open(fileobj=contents, mode="w:gz") as package:
                    for name, content in inputs.items():
                        info = tarfile.TarInfo(name)
                        info.size = len(content)
                        package.addfile(info, io.BytesIO(content))
                with tarfile.open(root / "build/licence_audit-1.0.0.tar", mode="w") as outer:
                    info = tarfile.TarInfo("contents.tar.gz")
                    info.size = len(contents.getvalue())
                    outer.addfile(info, io.BytesIO(contents.getvalue()))

            archive(files)
            hex_publish.check_package(root)
            for name in ["NOTICE", "src/main.gleam", "src/main_ffi.erl"]:
                with self.subTest(name=name):
                    archive({key: value for key, value in files.items() if key != name})
                    with self.assertRaises(KeyError):
                        hex_publish.check_package(root)
            archive({**files, "NOTICE": b"wrong notice"})
            with self.assertRaises(ValueError):
                hex_publish.check_package(root)
            archive({**files, "dev/helper.erl": b"dev code"})
            with self.assertRaises(ValueError):
                hex_publish.check_package(root)


if __name__ == "__main__":
    unittest.main()
