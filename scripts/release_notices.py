"""Stage and verify release notices. Missing runtime attribution blocks release."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile


APPLICATION = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt")
EMBEDDED = "META-INF/licenses/"


def required(path):
    data = path.read_bytes()
    if not data.strip():
        raise ValueError(f"Required notice material is empty: {path}")
    return data


def manifest_material(directory, prefix, mandatory):
    manifest = required(directory / "manifest.json")
    files = {prefix + "manifest.json": manifest}
    checksums = json.loads(manifest)["checksums"]
    if not set(mandatory).issubset(checksums):
        raise ValueError(f"Notice manifest lacks required documents: {directory}")
    for name, checksum in checksums.items():
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError(f"Invalid notice path: {name}")
        data = required(directory / name)
        if hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError(f"Notice checksum mismatch: {directory / name}")
        files[prefix + name] = data
    return files


def materials(target=None):
    files = {name: required(Path(name)) for name in APPLICATION}
    files.update(manifest_material(
        Path("slate_native/licenses"), "slate_native/licenses/",
        ("THIRD_PARTY_NOTICES.txt", "rust/COPYRIGHT-library.html"),
    ))
    if target:
        files.update(manifest_material(
            Path("build/release-notices") / target, "runtime-notices/",
            ("otp/bom.spdx.json", "queso/dependency-notices.json",
             "rust/COPYRIGHT-library.html", "openssl/LICENSE.txt", "otp-distribution.json"),
        ))
    return files


def embed(binary):
    files = materials()
    original = binary.read_bytes()
    with zipfile.ZipFile(binary) as archive:
        offset = min(member.header_offset for member in archive.infolist())
    # Escript reads the ZIP after its header, so ZIP offsets must stay relative.
    payload = io.BytesIO(original[offset:])
    with zipfile.ZipFile(payload, "a") as archive:
        for name, data in files.items():
            member = EMBEDDED + name
            if member in archive.namelist():
                if archive.read(member) != data:
                    raise ValueError(f"Stale embedded notice: {member}")
            else:
                archive.writestr(member, data)
    binary.write_bytes(original[:offset] + payload.getvalue())


def stage(destination, target=None):
    files = materials(target)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def check(path, target=None):
    files = materials(target)
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path) as archive:
            prefix = path.name.removesuffix(".tar.gz") + "/"
            contents = {}
            for name in files:
                member = archive.getmember(prefix + name)
                if not member.isfile():
                    raise ValueError(f"Required notice is not a regular file: {name}")
                contents[name] = archive.extractfile(member).read()
    else:
        with zipfile.ZipFile(path) as archive:
            prefix = "" if path.suffix == ".zip" else EMBEDDED
            contents = {name: archive.read(prefix + name) for name in files}
    for name, expected in files.items():
        if contents[name] != expected:
            raise ValueError(f"Missing or changed notice in {path}: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("embed", "stage", "check"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--target")
    args = parser.parse_args()
    try:
        if args.action == "embed":
            if args.target:
                parser.error("embed is only for the bare escript")
            embed(args.path)
        elif args.action == "stage":
            stage(args.path, args.target)
        else:
            check(args.path, args.target)
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Release notice validation failed: {error}\n")


if __name__ == "__main__":
    main()
