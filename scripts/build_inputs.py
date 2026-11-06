"""Download native build tools and verify committed SHA-256 pins before use."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parent.parent


def asset(tool, platform, manifest, tools):
    try:
        pin = manifest[tool]
        entry = pin["assets"][platform]
        version = pin["version"]
        url = entry["url"]
        digest = entry["sha256"]
    except (KeyError, TypeError) as error:
        raise ValueError(f"Missing build input pin: {tool} {platform}") from error
    configured = tools.get(tool)
    if isinstance(configured, dict):
        configured = configured["version"]
    if tool != "rustup" and configured != version:
        raise ValueError(f"Build input version differs from .mise.toml: {tool}")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"Build input version is not stable: {tool}")
    if not isinstance(url, str) or not url.startswith("https://") or version not in url:
        raise ValueError(f"Invalid versioned build input URL: {tool} {platform}")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError(f"Missing or invalid SHA-256 pin: {tool} {platform}")
    return entry


def verify(path, digest):
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != digest:
        raise ValueError(f"Build input checksum mismatch: {path}; expected {digest}, got {actual}")


def download(entry, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["curl", "--fail", "--location", "--retry", "3", entry["url"], "-o", str(destination)],
        check=True,
    )
    verify(destination, entry["sha256"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool")
    parser.add_argument("platform")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "scripts/build_inputs.json").read_text())
    tools = tomllib.loads((ROOT / ".mise.toml").read_text())["tools"]
    download(asset(args.tool, args.platform, manifest, tools), args.destination)


if __name__ == "__main__":
    main()
