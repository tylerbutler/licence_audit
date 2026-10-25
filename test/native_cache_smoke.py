"""Check a relocated release with real HTTPS and persistent SQLite cache hits."""

import argparse
from contextlib import closing
import importlib.util
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]


def run(command, work, env, name):
    result = subprocess.run(
        command, cwd=work, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, encoding="utf-8", errors="replace", timeout=180,
    )
    (work / f"{name}.log").write_text(result.stdout, encoding="utf-8")
    print(result.stdout, end="", flush=True)
    if result.returncode != 0:
        raise AssertionError(f"{name}: unexpected exit {result.returncode}")
    for line in result.stdout.splitlines():
        lower = line.lower()
        if any(text in lower for text in (
            "runtime terminating", "crash dump", "failed to eval", "noproc",
            "vulnerability check incomplete", "(details unavailable)",
        )):
            raise AssertionError(f"{name}: runtime failure: {line}")
        if re.search(r"\bWARN\s+\|", line) and not ("ipv6" in lower and "using ipv4" in lower):
            raise AssertionError(f"{name}: warning instead of a working release: {line}")
    return result.stdout


def smoke(binary, escript=False, bare=False):
    binary = binary.resolve(strict=True)
    work = ROOT / "build" / ("native-cache-smoke-" + uuid.uuid4().hex[:8])
    work.mkdir(parents=True)
    try:
        tools = work / "tools-é中"
        tools.mkdir()
        relocated = tools / ("licence_audit.exe" if binary.suffix == ".exe" else "licence_audit")
        shutil.copy2(binary, relocated)
        if escript and not bare:
            shutil.copytree(binary.parent / "sqlite_native", tools / "sqlite_native")
        for name in ("gleam.toml", "manifest.toml"):
            shutil.copy2(ROOT / "test/fixtures/native_http" / name, work / name)
        env = dict(os.environ)
        for name in ("ERL_LIBS", "ERL_FLAGS", "ERL_AFLAGS", "ERL_ZFLAGS"):
            env.pop(name, None)
        home = work / "home-é中"
        home.mkdir()
        scratch = work / "scratch"
        scratch.mkdir()
        env.update(
            HOME=str(home), USERPROFILE=str(home), XDG_CACHE_HOME=str(home / ".cache"),
            TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch),
            ERL_FLAGS="+S 2:2 +SDcpu 1 +SDio 1",
        )
        if not escript:
            env["PATH"] = (
                str(Path(os.environ["SystemRoot"]) / "System32") if os.name == "nt"
                else "/usr/bin:/bin:/usr/sbin:/sbin"
            )
            if shutil.which("erl", path=env["PATH"]):
                raise AssertionError("Native smoke test needs a runtime host without system Erlang")
        command = [str(relocated)]
        if escript and os.name == "nt":
            command.insert(0, shutil.which("escript") or "escript")
        cache = work / "cache-é中" / "metadata-é中.sqlite3"
        args = ["check", "--verbose", "--color=never", f"--cache-path={cache}"]
        if bare:
            result = subprocess.run(
                command + args, cwd=work, env=env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, encoding="utf-8", errors="replace", timeout=180,
            )
            print(result.stdout, end="")
            assert result.returncode == 0, result.stdout
            assert re.search(r"\bWARN\s+\|[^\n]*cache", result.stdout, re.IGNORECASE), result.stdout
            assert "Apache-2.0" in result.stdout, result.stdout
            assert not cache.exists(), "Bare escript unexpectedly wrote a cache"
        else:
            first = run(command + args, work, env, "fresh")
            assert "Apache-2.0" in first and "Cache hit for gleam_stdlib@1.0.5" not in first, first
            with closing(sqlite3.connect(cache)) as db:
                row = db.execute(
                    "SELECT value, cached_at FROM cache_entries WHERE key = ?",
                    ("gleam_stdlib@1.0.5",),
                ).fetchone()
                assert row and "Apache-2.0" in row[0] and isinstance(row[1], int), row
                assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
                assert db.execute("PRAGMA journal_mode").fetchone() == ("wal",)
            second = run(command + args, work, env, "cached")
            assert "Cache hit for gleam_stdlib@1.0.5" in second, second
            run(command + ["sbom", "--reproducible", "--offline", "--output=smoke-sbom.json"],
                work, env, "sbom")
            assert "pkg:hex/gleam_stdlib@1.0.5" in (work / "smoke-sbom.json").read_text()
            vulnerabilities = run(command + ["vulns", "--color=never"], work, env, "vulns")
            assert "Checked 1 packages:" in vulnerabilities, vulnerabilities
        print("Relocated SQLite/HTTPS smoke test passed.")
    except BaseException:
        print(f"Smoke test files retained at {work}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(work)


class StagingTests(unittest.TestCase):
    def test_compiled_only_and_missing_nif(self):
        spec = importlib.util.spec_from_file_location("sqlite_native", ROOT / "scripts/sqlite_native.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        work = ROOT / "build" / ("sqlite-stage-test-" + uuid.uuid4().hex[:8])
        source, destination = work / "compiled", work / "sidecar"
        try:
            for name in ("ebin/esqlite.beam", "ebin/esqlite.app", "priv/esqlite3_nif.so",
                         "priv/source/not-shipped.c", "src/not-shipped.erl"):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"compiled")
            module.stage(source, destination)
            self.assertEqual(
                sorted(path.relative_to(destination).as_posix()
                       for path in destination.rglob("*") if path.is_file()),
                ["ebin/esqlite.app", "ebin/esqlite.beam", "priv/esqlite3_nif.so"],
            )
            with self.assertRaises(ValueError):
                module.stage(source, work)
            with self.assertRaises(ValueError):
                module.stage(source, source / "sidecar")
            (source / "priv/esqlite3_nif.so").unlink()
            with self.assertRaises(ValueError):
                module.stage(source, destination)
            self.assertTrue((destination / "priv/esqlite3_nif.so").exists())
        finally:
            shutil.rmtree(work)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("binary", type=Path)
        parser.add_argument("--escript", action="store_true")
        parser.add_argument("--bare-escript", action="store_true")
        args = parser.parse_args()
        smoke(args.binary, args.escript or args.bare_escript, args.bare_escript)
