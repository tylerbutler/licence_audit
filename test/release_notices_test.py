import importlib.util
import io
import os
from pathlib import Path
import shutil
import tarfile
import unittest
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_notices", ROOT / "scripts/release_notices.py"
)
notices = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notices)


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
        (slate / "manifest.json").write_text('{"fixture": true}\n')
        (slate / "THIRD_PARTY_NOTICES.txt").write_text("Slate fixture\n")

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
        source = Path("native/notices") / target
        source.mkdir(parents=True)
        for name in notices.RUNTIME:
            with self.assertRaises(FileNotFoundError):
                notices.stage(Path("native"), target)
            (source / name).write_text(f"Reviewed runtime fixture: {name}\n")
        stage = Path("licence_audit-v1-x86_64-linux-glibc")
        notices.stage(stage, target)
        for extension in (".tar.gz", ".zip"):
            notices.check(self.archive(stage, extension), target)
        with self.assertRaises(FileNotFoundError):
            notices.stage(Path("other"), "aarch64-macos")

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
