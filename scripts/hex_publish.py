"""Publish eligible release tags to Hex without replacing existing releases."""

import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib
from urllib.error import HTTPError
from urllib.request import urlopen


def eligible(tag, version):
    if tag != f"v{version}":
        raise ValueError(f"Release tag {tag!r} does not match package version {version!r}.")
    number = r"(0|[1-9][0-9]*)"
    match = re.fullmatch(rf"v{number}\.{number}\.{number}(?:-rc\.{number})?", tag)
    return match is not None and int(match[1]) >= 1


def release_exists(version):
    url = f"https://hex.pm/api/packages/licence_audit/releases/{version}"
    try:
        with urlopen(url, timeout=30) as response:
            release = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    if release.get("version") != version:
        raise ValueError("Hex returned an unexpected release version.")
    return True


def check_package(root):
    config = tomllib.loads((root / "gleam.toml").read_text())
    archive = root / "build" / f"licence_audit-{config['version']}.tar"
    with tarfile.open(archive) as outer:
        contents = outer.extractfile("contents.tar.gz")
        with tarfile.open(fileobj=io.BytesIO(contents.read()), mode="r:gz") as package:
            required = [root / name for name in ["gleam.toml", "README.md", "LICENSE", "NOTICE"]]
            required += sorted((root / "src").rglob("*.gleam"))
            required += sorted((root / "src").rglob("*.erl"))
            for source in required:
                name = source.relative_to(root).as_posix()
                shipped = package.extractfile(name)
                if shipped is None or shipped.read() != source.read_bytes():
                    raise ValueError(f"Hex package has missing or changed input: {name}")
            for name in package.getnames():
                if name.startswith(("dev/", "test/", "native/dev/", "vendor/")):
                    raise ValueError(f"Hex package contains development input: {name}")
    print(f"Hex package source and licence material checked: {archive}")


def publish(tag):
    root = Path.cwd()
    config = tomllib.loads((root / "gleam.toml").read_text())
    if config["name"] != "licence_audit":
        raise ValueError("Expected the licence_audit package.")
    version = config["version"]
    if not eligible(tag, version):
        print(f"Skip Hex publication for {tag}: only stable 1.0.0+ and rc.N tags qualify.")
        return
    if release_exists(version):
        print(f"Hex already has licence_audit {version}; do not replace it.")
        return
    if not os.environ.get("HEXPM_API_KEY", "").strip():
        raise ValueError("Set the repository Actions secret HEXPM_API_KEY before publishing.")
    subprocess.run(["gleam", "export", "hex-tarball"], check=True)
    check_package(root)
    # Never use --replace: a competing publisher must fail, not overwrite Hex.
    subprocess.run(["gleam", "publish", "--yes"], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-package", action="store_true")
    parser.add_argument("tag", nargs="?")
    args = parser.parse_args()
    if args.check_package:
        check_package(Path.cwd())
    elif args.tag:
        publish(args.tag)
    else:
        parser.error("Provide a release tag or --check-package.")
