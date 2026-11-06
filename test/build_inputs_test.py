import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_inputs", ROOT / "scripts/build_inputs.py")
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class BuildInputsTest(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((ROOT / "scripts/build_inputs.json").read_text())
        self.config = tomllib.loads((ROOT / ".mise.toml").read_text())
        self.tools = self.config["tools"]

    def test_all_committed_assets_have_valid_pins(self):
        for tool, pin in self.manifest.items():
            for platform in pin["assets"]:
                with self.subTest(tool=tool, platform=platform):
                    inputs.asset(tool, platform, self.manifest, self.tools)

    def test_unknown_tool_or_platform_fails(self):
        for tool, platform in [("missing", "any"), ("gleam", "missing")]:
            with self.subTest(tool=tool, platform=platform):
                with self.assertRaisesRegex(ValueError, "Missing build input pin"):
                    inputs.asset(tool, platform, self.manifest, self.tools)

    def test_missing_or_malformed_hash_fails(self):
        for digest in [None, "", "sha256:" + "a" * 64, "z" * 64, "a" * 63]:
            manifest = copy.deepcopy(self.manifest)
            manifest["github:erlang/rebar3"]["assets"]["any"]["sha256"] = digest
            with self.subTest(digest=digest):
                with self.assertRaisesRegex(ValueError, "SHA-256 pin"):
                    inputs.asset("github:erlang/rebar3", "any", manifest, self.tools)
        del manifest["github:erlang/rebar3"]["assets"]["any"]["sha256"]
        with self.assertRaisesRegex(ValueError, "Missing build input pin"):
            inputs.asset("github:erlang/rebar3", "any", manifest, self.tools)

    def test_version_drift_fails(self):
        for tool in ["gleam", "github:erlang/rebar3", "github:jtdowney/queso"]:
            tools = dict(self.tools, **{tool: "99.0.0"})
            platform = next(iter(self.manifest[tool]["assets"]))
            with self.subTest(tool=tool):
                with self.assertRaisesRegex(ValueError, "version differs"):
                    inputs.asset(tool, platform, self.manifest, tools)

    def test_mutable_or_wrong_version_url_fails(self):
        for url in ["http://example.test/3.26.0", "https://example.test/latest", None]:
            manifest = copy.deepcopy(self.manifest)
            manifest["github:erlang/rebar3"]["assets"]["any"]["url"] = url
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, "versioned build input URL"):
                    inputs.asset("github:erlang/rebar3", "any", manifest, self.tools)

    def test_unstable_version_fails(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["rustup"]["version"] = "1.29.3-rc1"
        with self.assertRaisesRegex(ValueError, "not stable"):
            inputs.asset("rustup", "x86_64-unknown-linux-musl", manifest, self.tools)

    def test_verified_download_and_tampered_bytes(self):
        data = b"verified build tool\n"
        entry = {"url": "https://example.test/1.0.0", "sha256": hashlib.sha256(data).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool"
            for content in [data, data[:-1], b"tampered"]:
                with self.subTest(content=content):
                    def fetch(args, check):
                        self.assertTrue(check)
                        self.assertEqual(args[:5], ["curl", "--fail", "--location", "--retry", "3"])
                        self.assertEqual(args[5], entry["url"])
                        Path(args[-1]).write_bytes(content)

                    with mock.patch.object(inputs.subprocess, "run", side_effect=fetch):
                        if content == data:
                            inputs.download(entry, destination)
                        else:
                            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                                inputs.download(entry, destination)

    def test_failed_download_does_not_verify_stale_file(self):
        with mock.patch.object(inputs.subprocess, "run",
                               side_effect=subprocess.CalledProcessError(22, "curl")):
            with mock.patch.object(inputs, "verify") as verify:
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(subprocess.CalledProcessError):
                        inputs.download({"url": "https://example.test", "sha256": "a" * 64},
                                        Path(directory) / "tool")
                verify.assert_not_called()

    def test_workflow_versions_match_stable_toolchain(self):
        self.assertRegex(self.tools["gleam"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(self.tools["just"], r"^\d+\.\d+\.\d+$")
        for name in ["ci.yml", "native-build.yml"]:
            workflow = (ROOT / ".github/workflows" / name).read_text()
            for key, tool in [("gleam-version", "gleam"), ("otp-version", "erlang"),
                              ("rebar3-version", "github:erlang/rebar3")]:
                version = self.tools[tool]
                if isinstance(version, dict):
                    version = version["version"]
                self.assertIn(f'{key}: "{version}"', workflow)
        setup = (ROOT / ".github/actions/setup/action.yml").read_text()
        self.assertIn("install_args: --locked", setup)
        self.assertTrue(self.config["settings"]["lockfile"])
        lock = tomllib.loads((ROOT / "mise.lock").read_text())
        for tool in self.tools:
            version = self.tools[tool]
            if isinstance(version, dict):
                version = version["version"]
            self.assertTrue(all(pin["version"] == version for pin in lock["tools"][tool]))
        for tool in ["gleam", "just", "erlang", "github:erlang/rebar3"]:
            platforms = {key.removeprefix("platforms."): value for pin in lock["tools"][tool]
                         for key, value in pin.items() if key.startswith("platforms.")}
            self.assertEqual(set(platforms), {"linux-x64", "linux-arm64", "macos-x64", "macos-arm64"})
            for value in platforms.values():
                self.assertRegex(value["checksum"], r"^sha256:[a-f0-9]{64}$")

    def test_native_downloads_are_checked_before_use(self):
        script = (ROOT / "scripts/native_build.sh").read_text()
        self.assertNotIn("curl --", script)
        self.assertNotIn("sh.rustup.rs", script)
        self.assertEqual(script.count("scripts/build_inputs.py"), 5)
        for tool, destination, use in [
            ("gleam", "gleam.tar.gz", "tar -xzf build/native-tools/gleam.tar.gz"),
            ("github:erlang/rebar3", "rebar3", "chmod +x build/native-tools/rebar3"),
            ("rustup", "rustup-init", "chmod +x build/native-tools/rustup-init"),
            ("github:jtdowney/queso", "queso.zip", "python3 -m zipfile -e"),
            ("github:jtdowney/queso", "queso.tar.gz", "tar -xzf build/native-tools/queso.tar.gz"),
        ]:
            with self.subTest(tool=tool, destination=destination):
                line = next(line for line in script.splitlines()
                            if f"scripts/build_inputs.py {tool} " in line
                            and line.endswith("build/native-tools/" + destination))
                self.assertLess(script.index(line), script.index(use))
        platforms = self.manifest["github:jtdowney/queso"]["assets"]
        self.assertEqual(set(platforms), {
            "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
            "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-pc-windows-msvc",
        })


if __name__ == "__main__":
    unittest.main()
