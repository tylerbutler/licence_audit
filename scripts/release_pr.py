"""Prepare release PRs without automatic pushes replacing prerelease requests."""

import os
from pathlib import Path
import subprocess
import tomllib


def is_prerelease(manifest):
    version = tomllib.loads(manifest)["version"]
    return "-" in version.split("+", 1)[0]


def prepare(event, pre="", version=""):
    if event != "workflow_dispatch":
        if is_prerelease(Path("gleam.toml").read_text()):
            print("Main contains a prerelease; dispatch the next candidate or promotion.")
            return False
        pending = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet",
             "refs/remotes/origin/release/pending"],
        )
        if pending.returncode == 0:
            manifest = subprocess.run(
                ["git", "show", "origin/release/pending:gleam.toml"],
                check=True, capture_output=True, text=True,
            ).stdout
            if is_prerelease(manifest):
                print("The pending PR contains a prerelease; leave it unchanged.")
                return False
        elif pending.returncode != 1:
            pending.check_returncode()

    args = ["trellis", "release", "pr", "--base", "main", "--branch", "release/pending"]
    if pre.strip():
        args.extend(["--pre", pre.strip()])
    if version.strip():
        args.extend(["--set", f"licence_audit={version.strip()}"])
    subprocess.run(args, check=True)
    return True


if __name__ == "__main__":
    if os.environ["GITHUB_REF"] != "refs/heads/main":
        raise SystemExit("Run release preparation on main.")
    prepared = prepare(
        os.environ["GITHUB_EVENT_NAME"],
        os.environ.get("INPUT_PRE", ""),
        os.environ.get("INPUT_VERSION", ""),
    )
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"prepared={str(prepared).lower()}\n")
