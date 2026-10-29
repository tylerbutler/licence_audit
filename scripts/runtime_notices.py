"""Collect upstream runtime attribution from the inputs used by Queso."""

import argparse
import email
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib
import urllib.parse
import urllib.request


SOURCES = {}
DOWNLOADS = Path("build/runtime-notices-downloads")
RUST_TARGETS = {
    "aarch64-linux-glibc": "aarch64-unknown-linux-gnu",
    "x86_64-linux-glibc": "x86_64-unknown-linux-gnu",
    "aarch64-linux-musl": "aarch64-unknown-linux-musl",
    "x86_64-linux-musl": "x86_64-unknown-linux-musl",
    "aarch64-macos": "aarch64-apple-darwin",
    "x86_64-macos": "x86_64-apple-darwin",
    "x86_64-windows": "x86_64-pc-windows-gnu",
}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def fetch(url, digest=None):
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    path = DOWNLOADS / hashlib.sha256(url.encode()).hexdigest()
    if not path.exists():
        request = urllib.request.Request(url, headers={"User-Agent": "licence_audit release notices"})
        if url.startswith("https://api.github.com/") and os.environ.get("GH_TOKEN"):
            request.add_header("Authorization", "Bearer " + os.environ["GH_TOKEN"])
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data = response.read()
        except OSError as error:
            raise ValueError(f"Cannot fetch upstream material {url}: {error}") from error
        path.write_bytes(data)
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if digest and actual != digest.removeprefix("sha256:"):
        raise ValueError(f"Upstream checksum mismatch: {url}; expected {digest}, got {actual}")
    SOURCES[url] = {"sha256": actual}
    return data


def api(path):
    return json.loads(fetch("https://api.github.com/repos/" + path))


def raw(repo, revision, path):
    return fetch(f"https://raw.githubusercontent.com/{repo}/{revision}/{path}")


def release_asset(repo, tag, name):
    release = api(f"{repo}/releases/tags/{tag}")
    asset = next((asset for asset in release["assets"] if asset["name"] == name), None)
    if asset is None:
        raise ValueError(f"Required runtime asset is missing: {repo} {tag} {name}")
    if not asset.get("digest", "").startswith("sha256:"):
        raise ValueError(f"No published asset checksum: {repo} {name}")
    return asset


def otp_material(version):
    tag = "OTP-" + version
    asset = release_asset("erlang/otp", tag, "bom.spdx.json")
    bom = fetch(asset["browser_download_url"], asset["digest"])
    document = json.loads(bom)
    revision = api(f"erlang/otp/commits/{tag}")["sha"]
    files = {"otp/bom.spdx.json": bom}
    notices = ["Erlang/OTP " + version, "Upstream source inventory (a superset of bundled OTP applications).", ""]
    notices.extend(
        f"{package['name']} {package.get('versionInfo', '')}: {package.get('licenseDeclared', '')}"
        for package in document["packages"]
    )
    notices.extend(sorted({file["copyrightText"] for file in document["files"]
                           if file.get("copyrightText") not in (None, "NONE", "NOASSERTION")}))
    notices.extend(
        license["licenseId"] + "\n" + license["extractedText"]
        for license in document.get("hasExtractedLicensingInfos", [])
    )
    files["otp/THIRD_PARTY_NOTICES.txt"] = "\n\n".join(notices).encode()
    tree = api(f"erlang/otp/git/trees/{revision}?recursive=1")
    if tree.get("truncated"):
        raise ValueError("OTP source licence inventory is truncated")
    for entry in tree["tree"]:
        path = entry["path"]
        if entry["type"] == "blob" and (
            path == "LICENSE.txt" or path.startswith("LICENSES/")
            or path.startswith("erts/emulator/") and re.search(r"/LICEN[CS]E[^/]*$", path, re.I)
        ):
            files["otp/source/" + path] = raw("erlang/otp", revision, path)
    expressions = []
    for package in document["packages"]:
        expressions.extend(package.get(key, "") for key in ("licenseDeclared", "licenseConcluded"))
    for file in document["files"]:
        expressions.extend(file.get("licenseInfoInFiles", []))
    identifiers = set(re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", " ".join(expressions)))
    for identifier in sorted(identifiers - {"AND", "OR", "WITH", "NONE", "NOASSERTION"}):
        if not identifier.startswith("LicenseRef-"):
            files[f"otp/spdx/{identifier}.txt"] = raw(
                "spdx/license-list-data", "v3.27.0", f"text/{identifier}.txt"
            )
    return files


def wheel_tags(python, abi, platform):
    return {f"{p}-{a}-{s}" for p in python.split(".")
            for a in abi.split(".") for s in platform.split(".")}


def wheel_metadata_tags(wheel):
    return {expanded for tag in email.message_from_string(wheel).get_all("Tag", [])
            for expanded in wheel_tags(*"".join(tag.split()).split("-"))}


def toolchain_material(targets):
    rust = Path(command("rustc", "--print", "sysroot")) / "share/doc/rust"
    files = {"rust/COPYRIGHT-library.html": (rust / "COPYRIGHT-library.html").read_bytes()}
    for path in sorted((rust / "licenses").glob("*.txt")):
        files["rust/licenses/" + path.name] = path.read_bytes()
    if "rust/licenses/LLVM-exception.txt" not in files:
        raise ValueError("Rust toolchain licence texts are missing; install rust-docs")
    spec = importlib.util.find_spec("ziglang")
    if spec is None or spec.origin is None:
        raise ValueError("Zig package is missing; install the pinned ziglang packaging dependency")
    zig = Path(spec.origin).parent
    for path in sorted(zig.rglob("*")):
        if path.is_file() and path.name.lower().startswith(
            ("license", "licence", "copying", "copyright", "notice")
        ):
            files["zig/" + path.relative_to(zig).as_posix()] = path.read_bytes()
    if "zig/lib/libc/mingw/COPYING" not in files:
        raise ValueError("Zig bundled native licence material is missing")
    files["toolchain-versions.txt"] = (
        command("rustc", "--version") + "\nziglang "
        + importlib.metadata.version("ziglang") + "\n"
    ).encode()
    rust_version = command("rustc", "--version").split()[1]
    host = re.search(r"^host: (\S+)$", command("rustc", "-vV"), re.M)[1]
    url = f"https://static.rust-lang.org/dist/channel-rust-{rust_version}.toml"
    checksum = fetch(url + ".sha256").decode().split()[0]
    distribution = tomllib.loads(fetch(url, checksum).decode())
    packages = {}
    for package, triples in (
        ("rustc", [host]), ("rust-docs", [host]),
        ("rust-std", sorted({RUST_TARGETS[target] for target in targets})),
    ):
        packages[package] = {
            triple: distribution["pkg"][package]["target"][triple] for triple in triples
        }
    files["rust/distribution.json"] = json.dumps(packages, indent=2).encode()
    zig_version = importlib.metadata.version("ziglang")
    wheel = importlib.metadata.distribution("ziglang").read_text("WHEEL")
    if not wheel:
        raise ValueError("Installed Zig wheel metadata is missing")
    tags = wheel_metadata_tags(wheel)
    wheels = json.loads(fetch(f"https://pypi.org/pypi/ziglang/{zig_version}/json"))["urls"]
    matches = []
    for asset in wheels:
        if asset["filename"].endswith(".whl"):
            asset_tags = wheel_tags(*asset["filename"].removesuffix(".whl").rsplit("-", 3)[1:])
            if asset_tags == tags:
                matches.append({"url": asset["url"], "sha256": asset["digests"]["sha256"]})
    if len(matches) != 1:
        raise ValueError("Cannot identify the installed Zig wheel from its package metadata")
    files["zig/distribution.json"] = json.dumps(matches[0], indent=2).encode()
    return files


def launcher_material(cache, version, targets):
    candidates = sorted((cache / "launcher-build").glob(f"{version}-*/launcher/Cargo.lock"))
    if len(candidates) != 1:
        raise ValueError(f"Expected one fresh Queso {version} launcher lockfile in {cache}")
    lock = candidates[0]
    revision = api(f"jtdowney/queso/commits/v{version}")["sha"]
    if lock.read_text(encoding="utf-8") != raw(
        "jtdowney/queso", revision, "launcher/Cargo.lock"
    ).decode("utf-8"):
        raise ValueError("Built Queso launcher lockfile differs from pinned upstream source")
    config = Path("build/runtime-notices-about.toml")
    config.write_text(
        'accepted = ["Apache-2.0", "MIT", "BSD-3-Clause", "BSD-2-Clause", '
        '"ISC", "Unicode-3.0", "Zlib", "BSL-1.0", "MPL-2.0"]\n'
        'ignore-dev-dependencies = true\n[private]\nignore = true\n'
    )
    args = [
        "cargo", "about", "generate", "--locked", "--fail", "--format", "json",
        "--config", str(config), "--manifest-path", str(lock.with_name("Cargo.toml")),
    ]
    for target in targets:
        args.extend(("--target", RUST_TARGETS[target]))
    notices = command(*args).encode()
    document = json.loads(notices)
    if not document["licenses"]:
        raise ValueError("Queso launcher dependency notices are empty")
    readable = []
    for license in document["licenses"]:
        readable.append(", ".join(
            user["crate"]["name"] + " " + user["crate"]["version"]
            for user in license["used_by"]
        ) + "\n\n" + license["text"])
    source_packages = []
    for package in tomllib.loads(lock.read_text())["package"]:
        if package.get("source", "").startswith("registry+"):
            name, package_version = package["name"], package["version"]
            source_packages.append({
                "name": name, "version": package_version,
                "url": f"https://static.crates.io/crates/{name}/{name}-{package_version}.crate",
                "sha256": package["checksum"],
            })
    files = {
        "queso/LICENSE": raw("jtdowney/queso", revision, "LICENSE"),
        "queso/Cargo.lock": lock.read_bytes(),
        "queso/dependency-notices.json": notices,
        "queso/THIRD_PARTY_NOTICES.txt": "\n\n".join(readable).encode(),
        "queso/source-packages.json": json.dumps(source_packages, indent=2).encode(),
    }
    for crate in document["crates"]:
        package = crate["package"]
        root = Path(package["manifest_path"]).parent
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.name.lower().startswith(
                ("license", "licence", "copying", "copyright", "notice")
            ):
                prefix = f"queso/crates/{package['name']}-{package['version']}/"
                files[prefix + path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def debian_copyright(package, version):
    encoded = urllib.parse.quote(version, safe="")
    metadata = json.loads(fetch(
        f"https://snapshot.debian.org/mr/package/{package}/{encoded}/srcfiles"
    ))
    for entry in metadata["result"]:
        sha1 = entry["hash"]
        info = json.loads(fetch(f"https://snapshot.debian.org/mr/file/{sha1}/info"))
        if any(".debian.tar." in item["name"] for item in info["result"]):
            data = fetch(f"https://snapshot.debian.org/file/{sha1}")
            if hashlib.sha1(data).hexdigest() != sha1:
                raise ValueError(f"Debian source checksum mismatch: {package} {version}")
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                return archive.extractfile("debian/copyright").read()
    raise ValueError(f"Debian copyright source missing: {package} {version}")


def native_material(root, target, version, build_log=None):
    if target.endswith("-macos"):
        arch = "arm64" if target.startswith("aarch64") else "amd64"
        repo, name = "erlef/otp_builds", f"OTP-{version}-macos-{arch}.tar.gz"
    elif target.endswith("-windows"):
        repo, name = "erlang/otp", f"otp_win64_{version}.zip"
    else:
        arch = "arm64" if target.startswith("aarch64") else "x64"
        libc = "glibc" if target.endswith("-glibc") else "musl"
        repo, name = "gleam-community/erlang-linux-builds", f"erlang-{version}-{arch}-{libc}.tar.gz"
    asset = release_asset(repo, "OTP-" + version, name)
    if build_log is not None and (
        asset["browser_download_url"] not in build_log
        or asset["digest"].removeprefix("sha256:") not in build_log
    ):
        raise ValueError(f"Queso download URL/checksum does not match release metadata: {target}")
    files = {"otp-distribution.json": json.dumps({
        "target": target, "version": version, "url": asset["browser_download_url"],
        "sha256": asset["digest"].removeprefix("sha256:"),
        "checksum_source": "GitHub release asset metadata",
        "queso_download_verified": build_log is not None,
    }, indent=2).encode()}
    libraries = list(root.glob("lib/crypto-*/priv/lib/crypto.*"))
    versions = set()
    for library in libraries:
        versions.update(re.findall(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)\b", library.read_bytes()))
    if len(versions) != 1:
        raise ValueError(f"Cannot identify bundled OpenSSL from {root}/lib/crypto-*")
    openssl = versions.pop().decode()
    revision = api(f"openssl/openssl/commits/openssl-{openssl}")["sha"]
    for name in ("LICENSE.txt", "AUTHORS.md"):
        files["openssl/" + name] = raw("openssl/openssl", revision, name)
    files["openssl/version.txt"] = (openssl + "\n").encode()
    versions_file = root / "versions.txt"
    if "linux" in target:
        text = versions_file.read_text()
        files["otp-versions.txt"] = text.encode()
        if target.endswith("-glibc"):
            for binary, source in (("libssl-dev", "openssl"), ("libncurses-dev", "ncurses"),
                                   ("libgcc-12-dev", "gcc-12")):
                match = re.search(rf"^{binary}/[^\n]*,now (\S+)", text, re.M)
                if not match:
                    raise ValueError(f"No exact {binary} version in {versions_file}")
                files[f"debian/{source}-copyright"] = debian_copyright(source, match[1])
        else:
            musl = re.search(r"^musl-(\d+\.\d+\.\d+)-r\d+ ", text, re.M)
            gcc = re.search(r"^gcc-(\d+\.\d+\.\d+)-r\d+ ", text, re.M)
            ncurses = re.search(r"^ncurses-static-(\d+\.\d+)_p(\d+)-r\d+ ", text, re.M)
            if not all((musl, gcc, ncurses)):
                raise ValueError(f"No exact native component versions in {versions_file}")
            files["alpine/musl-COPYRIGHT"] = fetch(
                f"https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT?h=v{musl[1]}"
            )
            for name in ("COPYING3", "COPYING.RUNTIME"):
                files["alpine/gcc-" + name] = raw(
                    "gcc-mirror/gcc", "releases/gcc-" + gcc[1], name
                )
            alpine = re.search(r"^alpine-release-(\d+\.\d+)\.\d+-r\d+ ", text, re.M)
            if not alpine:
                raise ValueError(f"No Alpine release in {versions_file}")
            name = f"ncurses-{ncurses[1]}-{ncurses[2]}.tgz"
            commits = api("alpinelinux/aports/commits?sha=" + alpine[1]
                          + "-stable&path=main/ncurses/APKBUILD&until="
                          + asset["created_at"] + "&per_page=1")
            recipe = raw("alpinelinux/aports", commits[0]["sha"], "main/ncurses/APKBUILD").decode()
            checksum = re.search(rf"^([a-f0-9]{{128}})\s+{re.escape(name)}$", recipe, re.M)
            if not checksum:
                raise ValueError(f"No Alpine source checksum for {name}")
            data = fetch(f"https://distfiles.alpinelinux.org/distfiles/v{alpine[1]}/{name}")
            if hashlib.sha512(data).hexdigest() != checksum[1]:
                raise ValueError(f"Alpine ncurses source checksum mismatch: {name}")
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                member = next(member for member in archive if member.name.endswith("/COPYING"))
                files["alpine/ncurses-COPYING"] = archive.extractfile(member).read()
    return files


def write_bundle(destination, files):
    for name, data in files.items():
        if not data.strip():
            raise ValueError(f"Empty collected runtime material: {name}")
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = {
        "generator": "scripts/runtime_notices.py",
        "scope": "Upstream attribution superset; no legal review or runtime validation implied",
        "sources": SOURCES,
        "checksums": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append")
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--build-log", type=Path)
    args = parser.parse_args()
    mise = tomllib.loads(Path(".mise.toml").read_text())
    targets = args.target or tomllib.loads(Path("gleam.toml").read_text())["tools"]["queso"]["targets"]
    version = mise["tools"]["erlang"]
    queso = mise["tools"]["github:jtdowney/queso"]
    cache = args.cache or Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "queso"
    try:
        common = otp_material(version) | toolchain_material(targets) | launcher_material(cache, queso, targets)
        common["README.txt"] = (
            "Bundled runtime attribution\n\n"
            "OTP source licence/copyright inventories are a superset of bundled applications.\n"
            "queso/THIRD_PARTY_NOTICES.txt contains launcher dependency licence texts.\n"
            "For corresponding Rust dependency source, including MPL-2.0 dependencies,\n"
            "download the source archives listed in queso/source-packages.json;\n"
            "the recorded SHA-256 values come from the launcher's Cargo.lock.\n"
            "rust/ and zig/ preserve the build toolchains' bundled attribution.\n"
            "manifest.json records document checksums and upstream source locations.\n"
            "Collection preserves upstream material; it does not assert legal review.\n"
        ).encode()
        for target in targets:
            root = cache / "erts" / ("OTP-" + version) / target
            log = args.build_log.read_text() if args.build_log else None
            files = common | native_material(root, target, version, log)
            write_bundle(Path("build/release-notices") / target, files)
            print(f"Collected {len(files)} upstream runtime notice files: {target}")
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Runtime notice collection failed: {error}\n")


if __name__ == "__main__":
    main()
