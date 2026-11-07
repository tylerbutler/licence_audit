"""Continue release mode on pushes; change mode only on manual dispatch."""

import json
import os
from pathlib import Path
import subprocess
import tomllib


def release_mode(version):
    base, _, prerelease = version.split("+", 1)[0].partition("-")
    return base, prerelease.rsplit(".", 1)[0]


def git_stdout(*args):
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True,
    ).stdout.strip()


def new_candidate_changes():
    # RC fragments survive release; compare against the last version change.
    baseline = git_stdout(
        "log", "-1", "--format=%H", "-G", "^version[[:space:]]*=", "--", "gleam.toml",
    )
    if not baseline:
        raise RuntimeError("Cannot find the current release's version commit.")
    changed = subprocess.run([
        "git", "diff", "--quiet", baseline, "HEAD", "--",
        ":(glob).changes/unreleased/*.toml",
    ])
    if changed.returncode not in (0, 1):
        changed.check_returncode()
    return changed.returncode == 1


def prepare(event, pre="", version=""):
    if event != "workflow_dispatch":
        current = tomllib.loads(Path("gleam.toml").read_text())["version"]
        _, current_pre = release_mode(current)
        pending = json.loads(subprocess.run(
            ["gh", "pr", "list", "--head", "release/pending", "--base", "main",
             "--state", "open", "--json", "headRefOid,isCrossRepository"],
            check=True, capture_output=True, text=True,
        ).stdout)
        pending = [pr for pr in pending if not pr["isCrossRepository"]]
        if pending:
            manifest = git_stdout("show", f"{pending[0]['headRefOid']}:gleam.toml")
            target = tomllib.loads(manifest)["version"]
            base, target_pre = release_mode(target)
            if target_pre:
                pre, version = target_pre, base
            elif current_pre:
                pre, version = "none", ""
            else:
                pre, version = "", target
        elif current_pre:
            if not new_candidate_changes():
                print("No new fragments since the current candidate; nothing to prepare.")
                return False
            pre = current_pre

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
