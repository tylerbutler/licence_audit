"""Check the pinned Trellis binary and release workflow without remote writes."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import threading
import tomllib
import unittest


REPO = Path(__file__).resolve().parents[1]
WORKFLOW = (REPO / ".github/workflows/release.yml").read_text()
PREPARE = textwrap.dedent(
    WORKFLOW.split("      - name: Create or update release PR\n", 1)[1]
    .split("        run: |\n", 1)[1]
    .split("\n      - name:", 1)[0]
)


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.origin = Path(self.temp.name) / "origin.git"
        self.binary = shutil.which("trellis")
        self.assertIsNotNone(self.binary, "Run with mise exec -- or just test-release-pr.")
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.lower().endswith("_proxy") or key in {
                "GH_TOKEN", "GITHUB_TOKEN", "TRELLIS_GITHUB_API_URL",
                "TRELLIS_GITHUB_REPO", "GIT_DIR", "GIT_WORK_TREE",
            }:
                del self.env[key]
        self.env.update(
            GITHUB_TOKEN="test-token",
            TRELLIS_GITHUB_REPO="example/repo",
            TRELLIS_NO_UPDATE_CHECK="1",
            GITHUB_REF="refs/heads/main",
            GITHUB_EVENT_NAME="push",
            INPUT_PRE="",
            INPUT_VERSION="",
        )
        release = tomllib.loads((REPO / "gleam.toml").read_text())["tools"]["trellis"]["release"]
        self.write("gleam.toml", 'name = "licence_audit"\nversion = "0.9.0"\n'
                   '\n[tools.trellis.release]\n' + "".join(
                       f"{key} = {str(value).lower()}\n" for key, value in release.items()
                   ))
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", str(Path(self.temp.name) / "no-hooks"))
        self.commit()
        self.git("init", "-q", "--bare", str(self.origin))
        self.git("remote", "add", "origin", str(self.origin))
        self.pending = False
        self.requests = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, method):
                fixture.requests.append((method, self.path))
                if self.headers.get("Content-Length"):
                    self.rfile.read(int(self.headers["Content-Length"]))
                path = self.path.split("?", 1)[0]
                status, body = 200, {}
                if method == "GET" and path == "/repos/example/repo/pulls":
                    body = [fixture.pr()] if fixture.pending else []
                elif method == "GET" and path == "/repos/example/repo/pulls/7":
                    body = fixture.pr()
                elif method == "POST" and path == "/repos/example/repo/pulls":
                    fixture.pending = True
                    status, body = 201, {"number": 7, "html_url": "https://github.com/example/repo/pull/7"}
                elif method != "PATCH" or path != "/repos/example/repo/pulls/7":
                    status, body = 404, {"message": f"Unexpected test request: {method} {self.path}"}
                encoded = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self):
                self.respond("GET")

            def do_POST(self):
                self.respond("POST")

            def do_PATCH(self):
                self.respond("PATCH")

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()

        def stop_server():
            self.server.shutdown()
            thread.join()
            self.server.server_close()

        self.addCleanup(stop_server)
        self.env["TRELLIS_GITHUB_API_URL"] = f"http://127.0.0.1:{self.server.server_port}"
        bin_dir = Path(self.temp.name) / "bin"
        bin_dir.mkdir()
        shim = bin_dir / "mise"
        shim.write_text('#!/bin/sh\nset -eu\n[ "$1" = exec ] && [ "$2" = -- ]\nshift 2\nexec "$@"\n')
        shim.chmod(0o755)
        self.env["PATH"] = f"{bin_dir}{os.pathsep}{Path(self.binary).parent}{os.pathsep}{self.env['PATH']}"
        self.env["GITHUB_OUTPUT"] = str(Path(self.temp.name) / "output")

    def run_command(self, *args, success=True):
        result = subprocess.run(
            args, cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def git(self, *args):
        return self.run_command("git", *args).stdout.strip()

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "test inputs")

    def fragment(self, name, body):
        self.write(f".changes/unreleased/{name}.toml",
                   f'package = "licence_audit"\nkind = "Fixed"\nbody = "{body}"\n')
        self.commit()

    def pr(self):
        return {
            "number": 7, "state": "open", "html_url": "https://github.com/example/repo/pull/7",
            "head": {"ref": "release/pending", "sha": self.git("rev-parse", "origin/release/pending"),
                     "repo": {"full_name": "example/repo"}},
            "base": {"ref": "main", "repo": {"full_name": "example/repo"}},
        }

    def workflow(self, pre="", version="", event="workflow_dispatch", success=True):
        self.env.update(INPUT_PRE=pre, INPUT_VERSION=version, GITHUB_EVENT_NAME=event)
        output = Path(self.env["GITHUB_OUTPUT"])
        output.write_text("")
        result = self.run_command("bash", "-c", PREPARE, success=success)
        records = dict(line.split("=", 1) for line in output.read_text().splitlines())
        if success:
            self.assertEqual(records["schema"], "trellis.release_pr/1")
        else:
            self.assertEqual(records, {})
        return records, result

    def merge(self):
        self.git("merge", "--ff-only", "origin/release/pending")
        self.pending = False

    def test_candidate_continuation_archives_and_promotion(self):
        self.fragment("first", "first fix")
        records, _ = self.workflow(pre=" rc ", version=" 1.0.0 ")
        self.assertEqual(records["outcome"], "prepared")
        self.assertEqual(records["pr_action"], "created")
        self.assertEqual(json.loads(records["bumped"])[0]["next"], "1.0.0-rc.0")
        records, _ = self.workflow(event="push")
        self.assertEqual(records["outcome"], "unchanged")
        self.merge()
        self.assertFalse((self.root / ".changes/unreleased/first.toml").exists())
        self.assertIn("first fix", (self.root / ".changes/licence_audit/v1.0.0-rc.0.toml").read_text())
        self.write("README.md", "unrelated docs\n")
        self.commit()
        records, _ = self.workflow(event="push")
        self.assertEqual(records["outcome"], "unchanged")
        self.fragment("second", "second fix")
        records, _ = self.workflow(event="push")
        self.assertEqual(json.loads(records["bumped"])[0]["next"], "1.0.0-rc.1")
        self.merge()
        notes = (self.root / ".changes/licence_audit/v1.0.0-rc.1.md").read_text()
        self.assertIn("second fix", notes)
        self.assertNotIn("first fix", notes)
        _, result = self.workflow(success=False)
        self.assertIn("--pre none", result.stderr)
        records, _ = self.workflow(pre="none")
        self.assertEqual(json.loads(records["bumped"])[0]["next"], "1.0.0")
        self.fragment("late", "late fix")
        records, _ = self.workflow(event="push")
        self.assertEqual(records["outcome"], "prepared")
        self.assertEqual(records["pr_action"], "updated")
        self.assertEqual(json.loads(records["bumped"])[0]["next"], "1.0.0")
        self.merge()
        notes = (self.root / ".changes/licence_audit/v1.0.0.md").read_text()
        for body in ("first fix", "second fix", "late fix"):
            self.assertIn(body, notes)
        self.assertFalse(any("/releases" in path for _, path in self.requests))
        self.assertEqual(self.git("tag"), "")

    def test_source_changes_continue_candidates(self):
        self.fragment("first", "first fix")
        self.workflow(pre="rc", version="1.0.0")
        self.merge()
        self.write("src/runtime.txt", "changed release-owned source\n")
        self.commit()
        records, _ = self.workflow(event="push")
        self.assertEqual(json.loads(records["bumped"])[0]["next"], "1.0.0-rc.1")

    def test_legacy_pending_requires_manual_replacement(self):
        self.fragment("first", "legacy fix")
        manifest = (self.root / "gleam.toml").read_text()
        self.write("gleam.toml", manifest.replace("0.9.0", "1.0.0-rc.0"))
        self.write(".changes/licence_audit/v1.0.0-rc.0.md", "## 1.0.0-rc.0\n\n- legacy fix\n")
        self.commit()
        self.git("switch", "-c", "release/pending")
        self.write("gleam.toml", manifest.replace("0.9.0", "1.0.0-rc.1"))
        self.write(".changes/licence_audit/v1.0.0-rc.1.md", "## 1.0.0-rc.1\n\n- legacy fix\n")
        self.commit()
        self.git("push", "origin", "HEAD:release/pending")
        self.git("switch", "main")
        self.pending = True
        before = self.git("rev-parse", "origin/release/pending")
        records, result = self.workflow(event="push", success=False)
        self.assertIn("no native release intent", result.stderr)
        self.assertEqual(self.git("rev-parse", "origin/release/pending"), before)
        records, _ = self.workflow(pre="rc", version="1.0.0")
        self.assertEqual(records["outcome"], "prepared")
        self.assertEqual(json.loads(records["bumped"])[0]["next"], "1.0.0-rc.1")
        self.assertIn("pre = \"rc\"", self.git("show", "origin/release/pending:.changes/release.toml"))
        self.assertEqual(self.workflow(event="push")[0]["outcome"], "unchanged")
        self.merge()
        self.assertIn("legacy fix", (self.root / ".changes/licence_audit/v1.0.0-rc.1.toml").read_text())
        self.assertFalse((self.root / ".changes/unreleased/first.toml").exists())
        self.assertEqual(self.workflow(event="push")[0]["outcome"], "unchanged")
        self.workflow(pre="none")
        self.merge()
        self.assertIn("legacy fix", (self.root / ".changes/licence_audit/v1.0.0.md").read_text())

    def test_no_changes_main_guard_and_artifact_condition(self):
        self.assertEqual(self.run_command(self.binary, "--version").stdout.strip(), "trellis 1.3.0")
        self.assertEqual(self.workflow()[0]["outcome"], "no_changes")
        result = self.run_command(
            "just", "--justfile", str(REPO / "justfile"), "--working-directory", str(self.root),
            "release-pr", "--json",
        )
        self.assertEqual(json.loads(result.stdout)["outcome"], "no_changes")
        self.fragment("preview", "preview fix")
        result = self.run_command(
            "just", "--justfile", str(REPO / "justfile"), "--working-directory", str(self.root),
            "changelog-preview", "--pre", "rc", "--set", "licence_audit=1.0.0", "--json",
        )
        self.assertEqual(json.loads(result.stdout)["bumped"][0]["next"], "1.0.0-rc.0")
        self.env["GITHUB_REF"] = "refs/heads/other"
        _, result = self.workflow(success=False)
        self.assertIn("Run release preparation on main.", result.stderr)
        self.assertIn("if: steps.prepare.outputs.outcome == 'prepared'", WORKFLOW)
        refresh = WORKFLOW.split("      - name: Refresh generated release files\n", 1)[1]
        self.assertNotIn("git ls-remote", refresh)
        self.assertIn("set -euo pipefail\n          git fetch origin release/pending", refresh)


if __name__ == "__main__":
    unittest.main()
