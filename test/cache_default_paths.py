"""Check cache directory precedence and persistence in isolated Erlang VMs."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
EBIN = [str(path) for path in (ROOT / "build/dev/erlang").glob("*/ebin")]
ROUND_TRIP = """
    Override = case env_ffi:get(<<"CACHE_TEST_OVERRIDE">>) of
        {ok, Path} -> {some, Path};
        {error, nil} -> none
    end,
    Metadata = licence_audit@hex:licences_only([<<"MIT">>]),
    Cache = licence_audit@cache:open({enabled, Override}),
    none = licence_audit@cache:close(Cache),
    {{ok, Metadata}, none} = licence_audit@cache:fetch_cached_quiet(
        Cache, <<"example">>, <<"1.0.0">>, fun(_) -> {ok, Metadata} end),
    Reopened = licence_audit@cache:open({enabled, Override}),
    {{ok, Metadata}, none} = licence_audit@cache:fetch_cached_quiet(
        Reopened, <<"example">>, <<"1.0.0">>, fun(_) -> error(cache_miss) end),
    Notices = licence_audit@notice_cache:open({enabled, none}),
    none = licence_audit@notice_cache:close(Notices),
    none = licence_audit@notice_cache:put_text(Notices, <<"spdx:MIT">>, <<"MIT text">>),
    ReopenedNotices = licence_audit@notice_cache:open({enabled, none}),
    {{ok, <<"MIT text">>}, none} =
        licence_audit@notice_cache:get_text(ReopenedNotices, <<"spdx:MIT">>),
    halt().
"""


def run(expression, env, work):
    result = subprocess.run(
        ["erl", "-noshell", "-pa", *EBIN, "-eval", expression],
        cwd=work, env=env, capture_output=True, encoding="utf-8",
        errors="replace", timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def check_entry(directory, key, value):
    entries = list(directory.glob("*.json"))
    expected = directory / (hashlib.sha256(key.encode()).hexdigest() + ".json")
    assert entries == [expected], (directory, entries)
    entry = json.loads(expected.read_text(encoding="utf-8"))
    assert entry["key"] == key and value in entry["value"], entry
    assert not list(directory.glob("*.tmp")), directory


def main():
    (ROOT / "build").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="default-cache-", dir=ROOT / "build"))
    try:
        for case in ("xdg", "home", "home-empty-xdg", "override", "missing", "empty"):
            root = work / (case + "-é中")
            root.mkdir()
            env = dict(os.environ)
            for name in ("HOME", "XDG_CACHE_HOME", "CACHE_TEST_OVERRIDE",
                         "ERL_LIBS", "ERL_FLAGS", "ERL_AFLAGS", "ERL_ZFLAGS"):
                env.pop(name, None)
            env["ERL_FLAGS"] = "+S 2:2 +SDcpu 1 +SDio 1"
            env["LOCALAPPDATA"] = str(root / "Local")
            env["APPDATA"] = str(root / "Roaming")
            if case in ("xdg", "override"):
                env["XDG_CACHE_HOME"] = str(root / "xdg")
                env["HOME"] = str(root / "home")
                expected = root / "xdg" / "licence_audit"
            elif case in ("home", "home-empty-xdg"):
                env["HOME"] = str(root / "home")
                if case == "home-empty-xdg":
                    env["XDG_CACHE_HOME"] = ""
                expected = root / "home" / ".cache" / "licence_audit"
            else:
                if case == "empty":
                    env["HOME"] = env["XDG_CACHE_HOME"] = ""
                expected = root / "Local" / "licence_audit" / "Cache"
                if os.name != "nt":
                    run("""
                        Cache = licence_audit@cache:open({enabled, none}),
                        {some, Warning} = licence_audit@cache:close(Cache),
                        true = binary:match(Warning, <<"neither XDG_CACHE_HOME nor HOME">>) =/= nomatch,
                        none = licence_audit@cache:close(licence_audit@cache:open(disabled)),
                        halt().
                    """, env, root)
                    assert list(root.iterdir()) == [], list(root.iterdir())
                    continue
            metadata = expected / "hex-v2"
            if case == "override":
                metadata = root / "explicit"
                env["CACHE_TEST_OVERRIDE"] = str(metadata)
            run(ROUND_TRIP, env, root)
            check_entry(metadata, "example@1.0.0", "MIT")
            check_entry(expected / "notices-v3", "spdx:MIT", "MIT text")
            if case == "override":
                assert not (expected / "hex-v2").exists()
            if case in ("xdg", "override"):
                assert not (root / "home").exists()
            if case not in ("missing", "empty"):
                assert not (root / "Local").exists()
        print("Isolated default cache path tests passed.")
    finally:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
