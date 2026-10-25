"""Exercise the real Windows replacement path, including forced process death."""

import ctypes
from ctypes import wintypes
import os
import pathlib
import subprocess
import threading
import time


kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
kernel.CreateFileW.restype = wintypes.HANDLE
kernel.ReadFile.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
]
kernel.CloseHandle.argtypes = [wintypes.HANDLE]


def open_shared(path, sharing):
    handle = kernel.CreateFileW(str(path.resolve()), 0x80000000, sharing, None, 3, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def read_shared(path):
    handle = open_shared(path, 7)  # Readers must allow an atomic replacement.
    try:
        buffer = ctypes.create_string_buffer(65536)
        count = wintypes.DWORD()
        if not kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw[:count.value]
    finally:
        kernel.CloseHandle(handle)


root = pathlib.Path("build/windows-atomic")
root.mkdir(parents=True, exist_ok=False)
path = root / "policy ' & ü.toml"
original = b'# Keep this comment\nname = "keep_me"\n'
ebin = [str(directory) for directory in pathlib.Path("build/dev/erlang").glob("*/ebin")]


def start(mode, contents=""):
    environment = dict(
        os.environ, POLICY_TEST_PATH=str(path),
        POLICY_TEST_MODE=mode, POLICY_TEST_CONTENTS=contents,
    )
    return subprocess.Popen(
        ["erl", "-noshell", "-pa", *ebin, "-eval", "update_test_ffi:windows_worker()."],
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def finish(process):
    output, _ = process.communicate(timeout=120)
    assert process.returncode == 0 and "PASS" in output, (process.returncode, output)


def stop_tree(process):
    subprocess.run(
        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    process.communicate(timeout=30)


try:
    path.write_bytes(original)
    finish(start("update"))
    complete = read_shared(path)
    assert complete.startswith(original)
    assert b'allow = ["MIT-long-policy-entry"' in complete
    assert not list(root.glob("*.tmp"))
    print("PASS: existing-file update preserves comments and unrelated TOML")

    path.write_bytes(original)
    handle = open_shared(path, 3)  # No FILE_SHARE_DELETE: force replacement failure.
    try:
        finish(start("failure"))
        assert read_shared(path) == original
        assert not list(root.glob("*.tmp"))
    finally:
        kernel.CloseHandle(handle)
    print("PASS: failing native replacement preserves original and cleans temporary file")

    for delay in (0.01, 0.2, 0.5, 1.0):
        path.write_bytes(original)
        process = start("loop", complete.decode("utf-8"))
        stopped = threading.Event()
        failures = []
        observations = [0]

        def observe():
            while not stopped.is_set():
                try:
                    value = read_shared(path)
                    assert value in (original, complete), value
                    observations[0] += 1
                except Exception as error:
                    failures.append(error)
                    return

        watcher = threading.Thread(target=observe)
        watcher.start()
        try:
            assert process.stdout.readline().strip() == "REPLACED"
            time.sleep(delay)
            stop_tree(process)
            assert read_shared(path) in (original, complete)
        finally:
            if process.poll() is None:
                stop_tree(process)
            stopped.set()
            watcher.join()
        assert not failures, failures
        assert observations[0] > 0
        for temporary in root.glob("*.tmp"):
            temporary.unlink()
        print(f"PASS: process-tree interruption at {delay}s; {observations[0]} old-or-complete reads")
finally:
    for artifact in root.iterdir():
        artifact.unlink()
    root.rmdir()
