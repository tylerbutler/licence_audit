import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tarfile
import textwrap
import unittest
from unittest import mock
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_notices", ROOT / "scripts/release_notices.py"
)
notices = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notices)
RUNTIME_SPEC = importlib.util.spec_from_file_location(
    "runtime_notices", ROOT / "scripts/runtime_notices.py"
)
runtime = importlib.util.module_from_spec(RUNTIME_SPEC)
RUNTIME_SPEC.loader.exec_module(runtime)


class ReleaseNoticesTest(unittest.TestCase):
    def setUp(self):
        self.previous = Path.cwd()
        self.work = ROOT / "build/release-notices-tests" / uuid.uuid4().hex
        self.work.mkdir(parents=True)
        os.chdir(self.work)
        for name in notices.APPLICATION:
            Path(name).write_text(f"Application fixture: {name}\n")
        slate = Path("slate_native/licenses")
        slate.mkdir(parents=True)
        (slate / "THIRD_PARTY_NOTICES.txt").write_text("Slate fixture\n")
        (slate / "rust").mkdir()
        (slate / "rust/COPYRIGHT-library.html").write_text("Rust fixture\n")
        (slate / "manifest.json").write_text(json.dumps({
            "checksums": {
                name: hashlib.sha256((slate / name).read_bytes()).hexdigest()
                for name in ("THIRD_PARTY_NOTICES.txt", "rust/COPYRIGHT-library.html")
            }
        }))

    def tearDown(self):
        os.chdir(self.previous)
        shutil.rmtree(self.work)

    def archive(self, stage, extension):
        path = Path(stage.name + extension)
        if extension == ".zip":
            with zipfile.ZipFile(path, "w") as archive:
                for member in stage.rglob("*"):
                    if member.is_file():
                        archive.write(member, member.relative_to(stage))
        else:
            with tarfile.open(path, "w:gz") as archive:
                archive.add(stage, arcname=stage.name)
        return path

    def test_checks_archived_bytes_not_checkout_files(self):
        stage = Path("licence_audit-v1")
        notices.stage(stage)
        for extension in (".tar.gz", ".zip"):
            with self.subTest(extension=extension):
                archive = self.archive(stage, extension)
                notices.check(archive)
                (stage / "THIRD_PARTY_NOTICES.txt").write_text("Truncated\n")
                archive = self.archive(stage, extension)
                with self.assertRaisesRegex(ValueError, "Missing or changed"):
                    notices.check(archive)
                notices.stage(stage)

    def test_archive_missing_dependency_notices_fails(self):
        stage = Path("licence_audit-v1")
        notices.stage(stage)
        (stage / "THIRD_PARTY_NOTICES.txt").unlink()
        for extension in (".tar.gz", ".zip"):
            with self.subTest(extension=extension):
                with self.assertRaises(KeyError):
                    notices.check(self.archive(stage, extension))

    def test_missing_or_empty_source_material_fails(self):
        for name in (*notices.APPLICATION, "slate_native/licenses/THIRD_PARTY_NOTICES.txt"):
            with self.subTest(name=name):
                path = Path(name)
                original = path.read_bytes()
                path.write_text("")
                with self.assertRaisesRegex(ValueError, "empty"):
                    notices.stage(Path("stage"))
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    notices.stage(Path("stage"))
                path.write_bytes(original)

    def test_native_requires_all_target_specific_material(self):
        target = "x86_64-linux-glibc"
        source = Path("build/release-notices") / target
        source.mkdir(parents=True)
        names = ("otp/bom.spdx.json", "queso/dependency-notices.json",
                 "rust/COPYRIGHT-library.html", "openssl/LICENSE.txt", "otp-distribution.json")
        for name in names:
            with self.assertRaises(FileNotFoundError):
                notices.stage(Path("native"), target)
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"Upstream runtime fixture: {name}\n")
        (source / "manifest.json").write_text(json.dumps({
            "checksums": {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                          for name in names}
        }))
        stage = Path("licence_audit-v1-x86_64-linux-glibc")
        notices.stage(stage, target)
        for extension in (".tar.gz", ".zip"):
            notices.check(self.archive(stage, extension), target)
        with self.assertRaises(FileNotFoundError):
            notices.stage(Path("other"), "aarch64-macos")

    def test_slate_runtime_documents_are_required_and_checksum_verified(self):
        path = Path("slate_native/licenses/rust/COPYRIGHT-library.html")
        original = path.read_bytes()
        path.write_text("Corrupt\n")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            notices.stage(Path("stage"))
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            notices.embed(Path("licence_audit"))
        path.write_bytes(original)
        stage = Path("licence_audit-v1")
        notices.stage(stage)
        archived = stage / "slate_native/licenses/rust/COPYRIGHT-library.html"
        archived.write_text("Corrupt archived runtime notice\n")
        for extension in (".tar.gz", ".zip"):
            with self.subTest(extension=extension):
                with self.assertRaisesRegex(ValueError, "Missing or changed"):
                    notices.check(self.archive(stage, extension))
        notices.stage(stage)
        shutil.rmtree(stage / "slate_native/licenses/rust")
        for extension in (".tar.gz", ".zip"):
            with self.subTest(extension=extension):
                with self.assertRaises(KeyError):
                    notices.check(self.archive(stage, extension))

    def test_publish_stage_completes_and_checks_all_advertised_archives(self):
        workflow = (ROOT / ".github/workflows/publish.yml").read_text()
        step = workflow.split("- name: Stage release artifacts\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])
        targets = shlex.split(script.split("targets=(", 1)[1].split("\n)", 1)[0], comments=True)
        # These are packaging fixtures, not native executables or legal review.
        names = ("otp/bom.spdx.json", "queso/dependency-notices.json",
                 "rust/COPYRIGHT-library.html", "openssl/LICENSE.txt", "otp-distribution.json")
        for target in targets:
            destination = Path("build/release-notices") / target
            for name in names:
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Upstream notice fixture\n")
            (destination / "manifest.json").write_text(json.dumps({
                "checksums": {name: hashlib.sha256((destination / name).read_bytes()).hexdigest()
                              for name in names}
            }))
            binary = Path(f"build/queso/licence_audit-143-{target}"
                          + (".exe" if target.endswith("-windows") else ""))
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"Native executable fixture\n")
        Path(".validation/scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/release_notices.py", ".validation/scripts/")
        with zipfile.ZipFile("licence_audit", "w") as archive:
            archive.writestr("app.beam", b"Escript fixture")
        notices.embed(Path("licence_audit"))
        Path("dist").mkdir()
        Path("dist/licence_audit-v143.cdx.json").write_text('{"fixture": true}\n')
        result = subprocess.run(
            ["bash", "-c", script], env=os.environ | {"REF_NAME": "v143"},
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        checksums = subprocess.run(
            ["sha256sum", "-c", "checksums.txt"], cwd="dist", text=True, capture_output=True,
        )
        self.assertEqual(checksums.returncode, 0, checksums.stdout + checksums.stderr)
        for target in targets:
            extension = ".zip" if target.endswith("-windows") else ".tar.gz"
            notices.check(Path(f"dist/licence_audit-v143-{target}{extension}"), target)

    def test_runtime_download_rejects_published_checksum_mismatch(self):
        data = b"Corrupted upstream document"
        with mock.patch.object(runtime.urllib.request, "urlopen", return_value=io.BytesIO(data)):
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                runtime.fetch("https://example.invalid/otp-bom", "sha256:" + "0" * 64)

    def test_zig_wheel_identity_accepts_compressed_or_expanded_metadata(self):
        platforms = "manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64"
        asset = {
            "filename": f"ziglang-0.14.1-py3-none-{platforms}.whl",
            "url": "https://example.invalid/ziglang.whl",
            "digests": {"sha256": "published-wheel-checksum"},
        }
        expected = {"url": asset["url"], "sha256": asset["digests"]["sha256"]}
        for metadata in (
            f"Tag: py3-none-{platforms}\n",
            "\n".join(f"Tag: py3-none-{platform}" for platform in platforms.split(".")),
            f"Wheel-Version: 1.0\r\nTag: py3-none-{platforms}\r\n",
        ):
            with self.subTest(metadata=metadata):
                self.assertEqual(runtime.zig_wheel_distribution(metadata, [asset]), expected)

    def test_zig_wheel_identity_rejects_nonunique_or_invalid_metadata(self):
        asset = {
            "filename": "ziglang-0.14.1-py3-none-manylinux_2_12_x86_64.whl",
            "url": "https://example.invalid/ziglang.whl",
            "digests": {"sha256": "published-wheel-checksum"},
        }
        for metadata, assets in (
            ("Tag: py3-none-manylinux_2_12_aarch64", [asset]),
            ("Tag: py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64", [asset]),
            ("Tag: py3-none-manylinux_2_12_x86_64", [asset, asset]),
            ("Wheel-Version: 1.0", [asset]),
            ("Tag: malformed", [asset]),
            ("Tag: py3-none-", [asset]),
        ):
            with self.subTest(metadata=metadata, candidates=len(assets)):
                with self.assertRaises(ValueError):
                    runtime.zig_wheel_distribution(metadata, assets)

    def test_otp_collection_preserves_extracted_licences_and_copyright(self):
        bom = json.dumps({
            "packages": [{"name": "otp", "versionInfo": "28.3", "licenseDeclared": "Apache-2.0"}],
            "files": [{"copyrightText": "Copyright original author", "licenseInfoInFiles": ["MIT"]}],
            "hasExtractedLicensingInfos": [
                {"licenseId": "LicenseRef-example", "extractedText": "Original custom terms"}
            ],
        }).encode()
        with mock.patch.object(runtime, "release_asset", return_value={
            "browser_download_url": "https://example.invalid/bom", "digest": "sha256:fixture",
        }), mock.patch.object(runtime, "fetch", return_value=bom), \
                mock.patch.object(runtime, "api", side_effect=[
                    {"sha": "upstream-revision"},
                    {"tree": [{"path": "LICENSE.txt", "type": "blob"}]},
                ]), mock.patch.object(runtime, "raw", return_value=b"Full licence text"):
            files = runtime.otp_material("28.3")
        text = files["otp/THIRD_PARTY_NOTICES.txt"].decode()
        self.assertIn("Copyright original author", text)
        self.assertIn("Original custom terms", text)
        self.assertEqual(files["otp/bom.spdx.json"], bom)
        self.assertIn("otp/spdx/Apache-2.0.txt", files)
        self.assertIn("otp/spdx/MIT.txt", files)

    def test_external_ssl_version_comes_from_distribution_not_otp_source_bom(self):
        root = Path("otp")
        library = root / "lib/crypto-5.8/priv/lib/crypto.dll"
        library.parent.mkdir(parents=True)
        library.write_bytes(b"fixture\x00OpenSSL 3.1.0 14 Mar 2023\x00")
        with mock.patch.object(runtime, "release_asset", return_value={
            "browser_download_url": "https://example.invalid/otp.zip", "digest": "sha256:fixture",
        }), mock.patch.object(runtime, "api", return_value={"sha": "ssl-revision"}) as api, \
                mock.patch.object(runtime, "raw", return_value=b"Upstream SSL licence"):
            files = runtime.native_material(root, "x86_64-windows", "28.3")
            with self.assertRaisesRegex(ValueError, "download URL/checksum"):
                runtime.native_material(root, "x86_64-windows", "28.3", "Unmatched build log")
        api.assert_called_once_with("openssl/openssl/commits/openssl-3.1.0")
        self.assertEqual(files["openssl/version.txt"], b"3.1.0\n")

    def test_bare_escript_embeds_notices_without_replacing_payload(self):
        binary = Path("licence_audit")
        header = b"#!/usr/bin/env escript\n%%!\n"
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("app.beam", b"BEAM fixture")
        binary.write_bytes(header + payload.getvalue())
        binary.chmod(0o755)
        notices.embed(binary)
        notices.embed(binary)
        notices.check(binary)
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        with zipfile.ZipFile(binary) as archive:
            self.assertEqual(archive.read("app.beam"), b"BEAM fixture")
            self.assertEqual(len(archive.namelist()), len(set(archive.namelist())))
        self.assertTrue(binary.read_bytes().startswith(b"#!/usr/bin/env escript\n"))
        with zipfile.ZipFile(io.BytesIO(binary.read_bytes()[len(header):])) as archive:
            self.assertEqual(archive.infolist()[0].header_offset, 0)
        Path("NOTICE").write_text("Changed\n")
        with self.assertRaisesRegex(ValueError, "Stale embedded notice"):
            notices.embed(binary)


if __name__ == "__main__":
    unittest.main()
