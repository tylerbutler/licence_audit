"""After `just test`, run with `mise exec -- python3 -B test/update_atomic_macos.py`."""

import os
import pathlib
import subprocess
import sys
import tempfile


if sys.platform != "darwin":
    raise SystemExit("This regression requires macOS and its native ACL tools")

ebin = [str(path) for path in pathlib.Path("build/dev/erlang").glob("*/ebin")]
assert ebin, "Build the Erlang modules first"
root = pathlib.Path("build/tmp")
root.mkdir(parents=True, exist_ok=True)

with tempfile.TemporaryDirectory(prefix="update-acl-", dir=root) as directory:
    path = pathlib.Path(directory) / "policy \u00fc.toml"
    original = b'# Keep access rules\n[tools.licence_audit]\nallow = ["ISC"]\n'
    path.write_bytes(original)
    path.chmod(0o640)
    # Extended attributes can hide the ACL marker in ls's mode field.
    subprocess.run(
        ["/usr/bin/xattr", "-w", "com.apple.licence-audit-test", "acl-regression", str(path)],
        check=True,
    )
    subprocess.run(
        ["/bin/chmod", "+a", "everyone allow read,readsecurity", str(path)],
        check=True,
    )

    def acl():
        return subprocess.check_output(
            ["/bin/ls", "-lde", str(path)], text=True
        ).splitlines()[1:]

    before_acl = acl()
    assert before_acl and "everyone allow" in before_acl[0], before_acl
    before = path.stat()
    manifest = path.parent / "manifest.toml"
    manifest.write_text("packages = []\n")
    environment = dict(
        os.environ,
        POLICY_TEST_PATH=str(path),
        POLICY_TEST_MANIFEST=str(manifest),
        ERL_CRASH_DUMP=str(path.parent / "erl_crash.dump"),
    )
    for evaluation in [
        """
        Path = unicode:characters_to_binary(os:getenv("POLICY_TEST_PATH")),
        {error, nil} = policy_file_ffi:write(Path, <<"replacement">>),
        halt().
        """,
        """
        Path = unicode:characters_to_binary(os:getenv("POLICY_TEST_PATH")),
        Manifest = unicode:characters_to_binary(os:getenv("POLICY_TEST_MANIFEST")),
        Picker = fun(_, _, _, _) -> {ok, {selection, [<<"MIT">>], []}} end,
        {{update_diagnostic, 2, Message}, _} = licence_audit@update:run_with_picker(
            Manifest, <<".">>,
            {update_options, none, {some, Path}, verbose, never, true, none,
                none, none, false},
            licence_audit@notice:default_clients(), Picker,
            licence_audit@progress:capturing(verbose, <<"update">>)
        ),
        nomatch =/= binary:match(Message, <<"Failed to write">>) orelse error(Message),
        halt().
        """,
    ]:
        subprocess.run(
            ["erl", "-noshell", "-pa", *ebin, "-eval", evaluation],
            check=True,
            env=environment,
            timeout=30,
        )
        assert path.read_bytes() == original
        assert acl() == before_acl
        after = path.stat()
        assert (after.st_ino, after.st_mode, after.st_uid, after.st_gid) == (
            before.st_ino, before.st_mode, before.st_uid, before.st_gid
        )
        assert not list(path.parent.glob("*.licence-audit-*.tmp"))
    print("PASS: macOS ACL writes fail before replacement; original ACL and file intact")
