"""Check a relocated release with real HTTPS and persistent cache hits."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
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


def smoke(binary, escript=False):
    binary = binary.resolve(strict=True)
    work = ROOT / "build" / ("native-cache-smoke-" + uuid.uuid4().hex[:8])
    work.mkdir(parents=True)
    try:
        tools = work / "tools-é中"
        tools.mkdir()
        relocated = tools / ("licence_audit.exe" if binary.suffix == ".exe" else "licence_audit")
        shutil.copy2(binary, relocated)
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
        if os.name == "nt":
            env.pop("HOME", None)
            env.pop("XDG_CACHE_HOME", None)
            # Queso verifies Windows known folders before creating its cache.
            for name, folder in (("LOCALAPPDATA", "Local"), ("APPDATA", "Roaming")):
                path = home / "AppData" / folder
                path.mkdir(parents=True)
                env[name] = str(path)
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
        default_root = (
            Path(env["LOCALAPPDATA"]) / "licence_audit" / "Cache" if os.name == "nt"
            else home / ".cache" / "licence_audit"
        )
        for name, cache, overrides in (
            ("default", default_root / "hex-v2", []),
            ("override", work / "cache-é中" / "hex-v2",
             [f"--cache-dir={work / 'cache-é中'}"]),
        ):
            args = ["check", "--verbose", "--color=never", *overrides]
            first = run(command + args, work, env, f"{name}-fresh")
            assert "Apache-2.0" in first and "Cache hit for gleam_stdlib@1.0.5" not in first, first
            key = (
                "$immutable:v2:gleam_stdlib@1.0.5@hex:"
                "CEE5B6C076A85B45F60C585F4316C63EC8B7127C119D5738C3958A9C4D50404E"
            )
            entry_file = cache / (hashlib.sha256(key.encode()).hexdigest() + ".json")
            entry = json.loads(entry_file.read_text(encoding="utf-8"))
            assert entry["key"] == key, entry
            assert "Apache-2.0" in entry["value"] and entry.get("cached_at") is None, entry
            assert not list(cache.glob("*.tmp")), "Temporary cache files were left behind"
            second = run(command + args, work, env, f"{name}-cached")
            assert "Cache hit for gleam_stdlib@1.0.5" in second, second
        notices_args = ["notices", "--output=smoke-notices.txt", "--color=never"]
        run(command + notices_args, work, env, "notices-fresh")
        notices = (work / "smoke-notices.txt").read_bytes()
        notices_cache = default_root / "notices-v3"
        assert list(notices_cache.glob("*.json")), "Default notices cache is empty"
        assert not list(notices_cache.glob("*.tmp")), "Temporary notice cache files were left behind"
        run(command + notices_args, work, env, "notices-cached")
        assert (work / "smoke-notices.txt").read_bytes() == notices
        # Cold command families must not even prepare environment-default roots.
        isolated_env = dict(env)
        for name in ("HOME", "XDG_CACHE_HOME", "LOCALAPPDATA", "APPDATA"):
            isolated_env[name] = str(work / ("unused-" + name))
        for args, family, name in (
            (["--verbose", "--color=never"], "hex-v2", "default-report"),
            (["report", "--verbose", "--color=never"], "hex-v2", "named-report"),
            (notices_args, "notices-v3", "notices"),
            (["sbom", "--license-text", "--output=smoke-text.json", "--color=never"],
             "spdx-v1", "text"),
        ):
            explicit = work / ("explicit-é中-" + name)
            before = list(explicit.glob(f"{family}/*.json"))
            assert not before, (name, before)
            run(command + args + [f"--cache-dir={explicit}"],
                work, isolated_env, f"isolated-{name}-cold")
            entries = list(explicit.glob(f"{family}/*.json"))
            assert entries, f"Cold {name} cache is empty"
            snapshot = {file: file.read_bytes() for file in explicit.rglob("*.json")}
            run(command + args + [f"--cache-dir={explicit}"],
                work, isolated_env, f"isolated-{name}-warm")
            assert snapshot == {file: file.read_bytes() for file in explicit.rglob("*.json")}
            run(command + args + ["--no-cache"],
                work, isolated_env, f"isolated-{name}-bypass")
            assert snapshot == {file: file.read_bytes() for file in explicit.rglob("*.json")}
            for variable in ("HOME", "XDG_CACHE_HOME", "LOCALAPPDATA", "APPDATA"):
                default = Path(isolated_env[variable])
                if escript:
                    assert not default.exists(), variable
                elif default.exists():
                    # Queso unpacks its runtime before CLI option parsing.
                    assert {path.name for path in default.iterdir()} == {"licence_audit"}
                    assert {path.name for path in (default / "licence_audit").iterdir()} <= {
                        "app", "erts",
                    }, f"Application cache leaked into {variable}"
            assert not list(explicit.rglob("*.tmp"))
        run(command + ["sbom", "--reproducible", "--offline", "--output=smoke-sbom.json"],
            work, env, "sbom")
        assert "pkg:hex/gleam_stdlib@1.0.5" in (work / "smoke-sbom.json").read_text()
        vulnerabilities = run(command + ["vulns", "--color=never"], work, env, "vulns")
        assert "Checked 1 packages:" in vulnerabilities, vulnerabilities
        print("Relocated cache/HTTPS smoke test passed.")
    except BaseException:
        print(f"Smoke test files retained at {work}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(work)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--escript", action="store_true")
    args = parser.parse_args()
    smoke(args.binary, args.escript)
