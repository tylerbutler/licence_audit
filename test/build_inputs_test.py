from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BuildInputsTest(unittest.TestCase):
    def setUp(self):
        self.config = tomllib.loads((ROOT / ".mise.toml").read_text())
        self.tools = self.config["tools"]

    def test_workflow_versions_match_stable_toolchain(self):
        self.assertRegex(self.tools["gleam"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(self.tools["just"], r"^\d+\.\d+\.\d+$")
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        for key, tool in [("gleam-version", "gleam"), ("otp-version", "erlang"),
                          ("rebar3-version", "github:erlang/rebar3")]:
            version = self.tools[tool]
            if isinstance(version, dict):
                version = version["version"]
            self.assertIn(f'{key}: "{version}"', workflow)
        setup = (ROOT / ".github/actions/setup/action.yml").read_text()
        self.assertIn("install_args: --locked", setup)
        self.assertTrue(self.config["settings"]["lockfile"])
        self.assertEqual(self.config["settings"]["erlang"]["precompiled_os"], "ubuntu-24.04")
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


if __name__ == "__main__":
    unittest.main()
