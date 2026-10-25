"""Run the update flow under a file-size limit applied after VM startup (Linux)."""

import pathlib
import resource
import signal
import subprocess


root = pathlib.Path("build/tmp/update_sigxfsz")
root.mkdir(parents=True, exist_ok=False)
path = root / "gleam.toml"
original = b'# Must survive SIGXFSZ\nname = "keep_me"\n'
path.write_bytes(original)
path.chmod(0o640)
before = path.stat()

evaluation = """
io:format("READY~n"), io:get_line(""),
Fetcher = fun(_) -> {ok, licence_audit@hex:licences_only([<<"MIT">>])} end,
Picker = fun(_, _, _, _) ->
    {ok, {selection, lists:duplicate(1000, <<"MIT-long-policy-entry">>), []}}
end,
licence_audit@update:run_with_picker(
    <<"test/fixtures/transitive_manifest.toml">>, <<".">>,
    {some, <<"build/tmp/update_sigxfsz/gleam.toml">>}, true, true, none,
    Fetcher, Picker, licence_audit@progress:capturing(verbose, <<"update">>)
),
halt().
"""
ebin = [str(directory) for directory in pathlib.Path("build/dev/erlang").glob("*/ebin")]
process = subprocess.Popen(
    ["erl", "-noshell", "-pa", *ebin, "-eval", evaluation],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)
try:
    assert process.stdout.readline().strip() == "READY"
    resource.prlimit(process.pid, resource.RLIMIT_CORE, (0, 0))
    resource.prlimit(process.pid, resource.RLIMIT_FSIZE, (1024, 1024))
    output, _ = process.communicate(input="continue\n", timeout=20)
    assert process.returncode == -signal.SIGXFSZ, (process.returncode, output)
    assert path.read_bytes() == original
    after = path.stat()
    assert (before.st_mode, before.st_uid, before.st_gid) == (
        after.st_mode,
        after.st_uid,
        after.st_gid,
    )
    leftovers = list(root.glob("*.licence-audit-*.tmp"))
    assert len(leftovers) == 1
    assert leftovers[0].stat().st_size == 1024
    print("PASS: SIGXFSZ interrupts a partial temporary write; original intact")
finally:
    if process.poll() is None:
        process.kill()
        process.communicate()
    for artifact in root.iterdir():
        artifact.unlink()
    root.rmdir()
