"""Run after `just test-ffi`: `mise exec -- python3 -B test/picker_lifecycle.py`."""

import errno
import os
from pathlib import Path
import pty
import select
import socket
import struct
import subprocess
import tempfile
import termios
import time


ROOT = Path(__file__).resolve().parents[1]
EBIN = sorted(str(path) for path in (ROOT / "build/dev/erlang").glob("*/ebin"))
assert EBIN, "Run just test-ffi first"
TEMP = ROOT / "build/tmp"
TEMP.mkdir(parents=True, exist_ok=True)


def receive(connection):
    def exact(size):
        data = b""
        while len(data) < size:
            part = connection.recv(size - len(data))
            assert part, "VM closed the control connection"
            data += part
        return data

    return exact(struct.unpack("!I", exact(4))[0])


def send(connection, message):
    connection.sendall(struct.pack("!I", len(message)) + message)


def drain(master, output):
    while select.select([master], [], [], 0)[0]:
        try:
            part = os.read(master, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not part:
            break
        output.extend(part)


for mode, keys in [
    ("accept", b"d\r"),
    ("cancel", b"q"),
    ("escape", b"\x1b"),
    ("worker_failure", b""),
    ("reader_failure", b""),
    ("read_failure", b""),
]:
    with tempfile.TemporaryDirectory(prefix="picker-", dir=TEMP) as directory:
        path = Path(directory) / "gleam.toml"
        original = b'[tools.licence_audit]\nallow = ["ISC"]\ndeny = []\n'
        path.write_bytes(original)
        manifest = Path(directory) / "manifest.toml"
        manifest.write_text("packages = []\n")
        master, slave = pty.openpty()
        initial = termios.tcgetattr(slave)
        output = bytearray()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(15)
            environment = dict(
                os.environ,
                PICKER_POLICY_PATH=str(path),
                PICKER_MANIFEST_PATH=str(manifest),
                PICKER_TEST_MODE=mode,
                PICKER_CONTROL_PORT=str(listener.getsockname()[1]),
                ERL_CRASH_DUMP=str(Path(directory) / "erl_crash.dump"),
                TERM="xterm",
            )
            process = subprocess.Popen(
                ["erl", "-noshell", "-pa", *EBIN,
                 "-eval", "picker_lifecycle_test_ffi:run()."],
                cwd=ROOT, env=environment, stdin=slave, stdout=slave, stderr=slave,
            )
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(15)
                    assert receive(connection) == b"reader-ready"
                    assert process.poll() is None
                    if keys:
                        deadline = time.monotonic() + 10
                        while b"enter ok" not in output:
                            drain(master, output)
                            assert time.monotonic() < deadline, output.decode(errors="replace")
                            time.sleep(0.01)
                    send(connection, b"act")
                    if keys:
                        # One input read can contain both the selection and Enter.
                        os.write(master, keys)
                    assert receive(connection) == b"before-policy"
                    assert process.poll() is None, "Checkpoint must run in a live VM"
                    assert path.read_bytes() == original, "Policy written before checkpoint"
                    restored = termios.tcgetattr(slave)
                    mask = termios.ICANON | termios.ECHO
                    assert restored[3] & mask == initial[3] & mask, "Terminal not restored"
                    send(connection, b"continue")
                    assert receive(connection) == b"done"
                    if mode == "accept":
                        assert b'deny = ["ISC"]' in path.read_bytes()
                    else:
                        assert path.read_bytes() == original
                    send(connection, b"finish")
                process.wait(timeout=10)
                drain(master, output)
                assert process.returncode == 0, output.decode(errors="replace")
                diagnostic = b"Picker failed to read terminal input repeatedly."
                assert (diagnostic in output) == mode.endswith("failure"), output
                print(f"PASS: {mode}: reader dead before policy work; terminal restored")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                os.close(master)
                os.close(slave)
