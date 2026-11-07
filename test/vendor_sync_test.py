import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import vendor_sync


class VendorSyncTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "gleam.toml").write_text(
            '[dependencies]\ngleam_stdlib = ">= 1.0.0 and < 2.0.0"\n'
            '[dev_dependencies]\nglugify = ">= 3.0.0 and < 4.0.0"\n'
        )
        for name in vendor_sync.PACKAGES:
            package = self.root / "vendor" / name
            (package / "src").mkdir(parents=True)
            dependencies = (
                'gleam_stdlib = ">= 1.0.0 and < 2.0.0"'
                if name == "glint"
                else 'glint = { git = "https://example.com/glint", ref = "main" }\n'
                'glugify = ">= 3.0.0 and < 4.0.0"'
            )
            (package / "gleam.toml").write_text(
                f'name = "{name}"\nversion = "1.0.0"\n'
                f'licences = ["Apache-2.0"]\n[dependencies]\n{dependencies}\n'
            )
            (package / ".gitrepo").write_text(
                f"[subrepo]\nremote = https://example.com/{name}\ncommit = {'a' * 40}\n"
            )
            (package / "src" / f"{name}.gleam").write_text(
                "import glint/help\npub fn main() { Nil }\n"
            )
        (self.root / "vendor/glint/LICENSE").write_text("Apache-2.0 licence text\n")
        formatter = patch.object(vendor_sync, "format_gleam", side_effect=lambda text: text)
        formatter.start()
        self.addCleanup(formatter.stop)

    def test_rewrites_exact_imports_and_preserves_aliases_and_strings(self):
        text = (
            "import glint\nimport glint/help as help\n"
            "import glint_markdown\nimport glint_extra\n"
            'const example = "import glint/help"\n'
        )
        rewritten = vendor_sync.rewrite_source(
            text,
            ".gleam",
            {"glint": "vendor/glint", "glint/help": "vendor/glint/help"},
            {},
        )
        self.assertEqual(
            rewritten,
            "import vendor/glint\nimport vendor/glint/help as help\n"
            "import glint_markdown\nimport glint_extra\n"
            'const example = "import glint/help"\n',
        )

    def test_namespaces_erlang_ffi_without_changing_javascript_paths(self):
        ffi = {"exit_ffi": "licence_audit_vendor_exit_ffi"}
        gleam = (
            '@external(erlang, "exit_ffi", "exit")\n'
            '@external(javascript, "./exit_ffi.mjs", "exit")\n'
        )
        self.assertEqual(
            vendor_sync.rewrite_source(gleam, ".gleam", {}, ffi),
            '@external(erlang, "licence_audit_vendor_exit_ffi", "exit")\n'
            '@external(javascript, "./exit_ffi.mjs", "exit")\n',
        )
        self.assertEqual(
            vendor_sync.rewrite_source("-module(exit_ffi).\nexit_ffi:exit().\n", ".erl", {}, ffi),
            "-module(licence_audit_vendor_exit_ffi).\nlicence_audit_vendor_exit_ffi:exit().\n",
        )
        package = self.root / "vendor/glint/src"
        (package / "exit_ffi.erl").write_text("-module(exit_ffi).\n")
        generated = vendor_sync.generated_files(self.root)
        self.assertIn(
            Path("src") / vendor_sync.NAMESPACE / "licence_audit_vendor_exit_ffi.erl",
            generated,
        )

    def test_adapts_development_exit_without_copying_native_shims(self):
        package = self.root / "vendor/glint_markdown/src"
        for relative, text in vendor_sync.EXIT_NATIVE_FILES.items():
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        declarations = package / "glint_markdown/internal/exit.gleam"
        declarations.write_text(vendor_sync.EXIT_DECLARATIONS)
        generated = vendor_sync.generated_files(self.root)
        self.assertFalse(any(path.suffix in {".erl", ".mjs"} for path in generated))
        source = generated[Path("dev") / vendor_sync.NAMESPACE / "glint_markdown/internal/exit.gleam"]
        self.assertIn("io.print_error(message)", source)
        self.assertIn('@external(erlang, "erlang", "halt")', source)
        self.assertIn('@external(javascript, "node:process", "exit")', source)
        declarations.write_text(vendor_sync.EXIT_DECLARATIONS.replace('"stderr"', '"new_stderr"'))
        with self.assertRaisesRegex(ValueError, "Review the updated"):
            vendor_sync.generated_files(self.root)

    def test_rejects_native_development_sources_and_changed_shims(self):
        package = self.root / "vendor/glint_markdown/src"
        path = package / "extra.erl"
        path.write_text("-module(extra).\n")
        with self.assertRaisesRegex(ValueError, "native development sources"):
            vendor_sync.generated_files(self.root)
        path.unlink()
        relative = "glint_markdown/internal/glint_markdown_exit_ffi.erl"
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(vendor_sync.EXIT_NATIVE_FILES[relative] + "% New code\n")
        with self.assertRaisesRegex(ValueError, "Review the updated"):
            vendor_sync.generated_files(self.root)

    def test_separates_reviewed_native_development_sources_from_production(self):
        package = self.root / "vendor/glint_markdown/src"
        native_sources = {
            "glint_markdown_filesystem_ffi.erl": "-module(glint_markdown_filesystem_ffi).\n",
            "glint_markdown/internal/filesystem_ffi.mjs": 'import { Ok } from "../../gleam.mjs";\n',
        }
        for relative, text in native_sources.items():
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        declarations = package / "glint_markdown/internal/filesystem.gleam"
        declarations.write_text(
            '@external(erlang, "glint_markdown_filesystem_ffi", "canonical_path")\n'
            '@external(javascript, "./filesystem_ffi.mjs", "canonical_path")\n'
            "pub fn canonical_path(path: String) -> Result(String, String)\n"
        )
        fingerprints = {
            relative: hashlib.sha256(text.encode()).hexdigest()
            for relative, text in native_sources.items()
        }
        with patch.dict(vendor_sync.DEVELOPMENT_NATIVE_FILES, fingerprints):
            generated = vendor_sync.generated_files(self.root)
            erlang = Path("native/dev") / vendor_sync.NAMESPACE / "licence_audit_vendor_glint_markdown_filesystem_ffi.erl"
            javascript = Path("dev") / vendor_sync.NAMESPACE / "glint_markdown/internal/filesystem_ffi.mjs"
            self.assertIn(erlang, generated)
            self.assertIn("-module(licence_audit_vendor_glint_markdown_filesystem_ffi).", generated[erlang])
            self.assertIn('from "../../../../../gleam.mjs"', generated[javascript])
            source = generated[Path("dev") / vendor_sync.NAMESPACE / "glint_markdown/internal/filesystem.gleam"]
            self.assertIn('"licence_audit_vendor_glint_markdown_filesystem_ffi"', source)
            self.assertFalse(any(
                path.parts[0] in {"src", "dev", "test"} and path.suffix == ".erl"
                for path in generated
            ))
            vendor_sync.sync(self.root, check=False)
            self.assertEqual(vendor_sync.sync(self.root, check=True), [])
            stale = self.root / erlang.parent / "stale.erl"
            stale.write_text("-module(stale).\n")
            self.assertIn(stale.relative_to(self.root), vendor_sync.sync(self.root, check=True))
            (package / "glint_markdown_filesystem_ffi.erl").write_text("% Changed\n")
            with self.assertRaisesRegex(ValueError, "Review the updated native"):
                vendor_sync.generated_files(self.root)

    def test_separates_runtime_and_development_sources_and_preserves_notices(self):
        (self.root / "vendor/glint/NOTICE").write_text("Upstream attribution\n")
        generated = vendor_sync.generated_files(self.root)
        self.assertIn(Path("src") / vendor_sync.NAMESPACE / "glint.gleam", generated)
        self.assertIn(Path("dev") / vendor_sync.NAMESPACE / "glint_markdown.gleam", generated)
        self.assertNotIn(Path("src") / vendor_sync.NAMESPACE / "glint_markdown.gleam", generated)
        notice = generated[Path("NOTICE")]
        self.assertIn("development only", notice)
        self.assertIn("Upstream attribution", notice)
        self.assertIn("Apache-2.0 licence text", notice)
        source = generated[Path("src") / vendor_sync.NAMESPACE / "glint.gleam"]
        self.assertIn("Modified for licence_audit vendoring", source)
        self.assertIn("a" * 40, source)

    def test_check_reports_missing_changed_and_stale_files_without_writing(self):
        self.assertTrue(vendor_sync.sync(self.root, check=True))
        self.assertFalse((self.root / "NOTICE").exists())
        vendor_sync.sync(self.root, check=False)
        self.assertEqual(vendor_sync.sync(self.root, check=True), [])
        source = self.root / "src" / vendor_sync.NAMESPACE / "glint.gleam"
        source.write_text("Changed\n")
        stale = source.parent / "stale.gleam"
        stale.write_text("Stale\n")
        changed = vendor_sync.sync(self.root, check=True)
        self.assertIn(source.relative_to(self.root), changed)
        self.assertIn(stale.relative_to(self.root), changed)
        self.assertEqual(source.read_text(), "Changed\n")
        self.assertTrue(stale.exists())
        vendor_sync.sync(self.root, check=False)
        self.assertFalse(stale.exists())
        self.assertEqual(vendor_sync.sync(self.root, check=True), [])

    def test_rejects_missing_hex_dependencies_before_writing(self):
        config = self.root / "gleam.toml"
        config.write_text('[dependencies]\n[dev_dependencies]\n')
        with self.assertRaisesRegex(ValueError, "Hex dependency"):
            vendor_sync.sync(self.root, check=False)
        self.assertFalse((self.root / "NOTICE").exists())

    def test_rejects_runtime_dependencies_on_development_sources(self):
        metadata = self.root / "vendor/glint/gleam.toml"
        with metadata.open("a") as file:
            file.write('glint_markdown = { path = "../glint_markdown" }\n')
        with self.assertRaisesRegex(ValueError, "development-only dependency"):
            vendor_sync.generated_files(self.root)

    def test_rejects_licence_changes_and_unknown_source_files(self):
        metadata = self.root / "vendor/glint/gleam.toml"
        original = metadata.read_text()
        metadata.write_text(original.replace("Apache-2.0", "MIT"))
        with self.assertRaisesRegex(ValueError, "licence"):
            vendor_sync.generated_files(self.root)
        metadata.write_text(original)
        (self.root / "vendor/glint/src/asset.bin").write_bytes(b"\x00")
        with self.assertRaisesRegex(ValueError, "Unsupported vendored source"):
            vendor_sync.generated_files(self.root)

    def test_rejects_symlinked_output(self):
        directory = self.root / "src" / vendor_sync.NAMESPACE
        directory.mkdir(parents=True)
        outside = self.root / "unrelated.gleam"
        outside.write_text("Do not change\n")
        (directory / "glint.gleam").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            vendor_sync.sync(self.root, check=False)
        self.assertEqual(outside.read_text(), "Do not change\n")
