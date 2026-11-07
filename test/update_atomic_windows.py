"""Exercise Windows atomic replacement, private temporaries, and helper lifetime."""

import base64
import ctypes
from ctypes import wintypes
import os
import pathlib
import socket
import struct
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
kernel.GetCurrentProcess.restype = wintypes.HANDLE
kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.OpenProcess.restype = wintypes.HANDLE
kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel.WaitForSingleObject.restype = wintypes.DWORD
kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
kernel.GetFileAttributesW.restype = wintypes.DWORD
kernel.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
kernel.LocalFree.argtypes = [wintypes.HANDLE]
security = ctypes.WinDLL("advapi32", use_last_error=True)


class SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]


security.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
]
security.ConvertStringSidToSidW.argtypes = [
    wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID),
]
security.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(SidAndAttributes), ctypes.POINTER(wintypes.HANDLE),
]
security.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]


def check(value):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


def restricted_reader():
    token = wintypes.HANDLE()
    sid = wintypes.LPVOID()
    restricted = wintypes.HANDLE()
    check(security.OpenProcessToken(kernel.GetCurrentProcess(), 0xA, ctypes.byref(token)))
    try:
        check(security.ConvertStringSidToSidW("S-1-1-0", ctypes.byref(sid)))
        try:
            everyone = SidAndAttributes(sid, 0)
            check(security.CreateRestrictedToken(
                token, 1, 0, None, 0, None, 1, ctypes.byref(everyone),
                ctypes.byref(restricted),
            ))
        finally:
            kernel.LocalFree(sid)
    finally:
        kernel.CloseHandle(token)
    return restricted


def assert_private(path, token):
    check(security.ImpersonateLoggedOnUser(token))
    try:
        try:
            read_shared(path)
        except OSError as error:
            assert error.winerror == 5, error
        else:
            raise AssertionError(f"Restricted reader can read private file: {path}")
    finally:
        check(security.RevertToSelf())


def open_shared(path, sharing):
    handle = kernel.CreateFileW(str(path.absolute()), 0x80000000, sharing, None, 3, 0, None)
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
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(20)
    environment = dict(
        os.environ, POLICY_TEST_PATH=str(path),
        POLICY_TEST_MODE=mode, POLICY_TEST_CONTENTS=contents,
        POLICY_CONTROL_PORT=str(listener.getsockname()[1]),
    )
    try:
        process = subprocess.Popen(
            ["erl", "-noshell", "-pa", *ebin, "-eval", "update_test_ffi:windows_worker()."],
            env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        process.control, _ = listener.accept()
        return process
    finally:
        listener.close()


def command(process, message):
    data = message.encode("utf-8")
    process.control.sendall(struct.pack("!I", len(data)) + data)


def finish(process, input=None):
    if input is not None:
        command(process, input.strip())
    output, _ = process.communicate(timeout=120)
    process.control.close()
    assert process.returncode == 0 and "PASS" in output, (process.returncode, output)
    return output


def active_helper(process):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        markers = list(root.glob("*.helper"))
        if markers:
            marker = markers[0]
            content = marker.read_text()
            if content:
                handle = check(kernel.OpenProcess(0x100000, False, int(content)))
                assert kernel.WaitForSingleObject(handle, 0) == 258
                return marker, handle
        assert process.poll() is None, process.communicate()
        time.sleep(0.02)
    raise AssertionError("Native helper did not become ready")


def kill_owner(process):
    command(process, "kill-owner")
    assert process.stdout.readline().strip() == "OWNER_DEAD"


def security_descriptor(for_path=path):
    escaped_path = str(for_path.absolute()).replace("'", "''")
    script = (
        f"$path='{escaped_path}';"
        "[IO.File]::GetAccessControl($path).GetSecurityDescriptorSddlForm("
        "[Security.AccessControl.AccessControlSections]'Access,Owner,Group')"
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return subprocess.check_output(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        text=True,
    ).strip()


try:
    subprocess.run(
        ["icacls", str(root), "/grant", "*S-1-1-0:(OI)(CI)(RX)"],
        stdout=subprocess.DEVNULL, check=True,
    )
    reader = restricted_reader()
    public = root / "public.txt"
    public.write_bytes(b"readable")
    check(security.ImpersonateLoggedOnUser(reader))
    try:
        assert read_shared(public) == b"readable"
    finally:
        check(security.RevertToSelf())
    path.write_bytes(original)
    account = os.environ["USERDOMAIN"] + "\\" + os.environ["USERNAME"]
    subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", account + ":(F)"],
        stdout=subprocess.DEVNULL, check=True,
    )
    original_security = security_descriptor()
    assert_private(path, reader)
    finish(start("update"))
    complete = read_shared(path)
    assert complete.startswith(original)
    assert b'allow = ["MIT-long-policy-entry"' in complete
    assert security_descriptor() == original_security, (
        security_descriptor(), original_security,
    )
    assert not list(root.glob("*.tmp"))
    print("PASS: existing-file update preserves comments, unrelated TOML, owner/group/DACL")

    path.write_bytes(original)
    handle = open_shared(path, 3)  # No FILE_SHARE_DELETE: force replacement failure.
    try:
        finish(start("failure"))
        assert read_shared(path) == original
        assert not list(root.glob("*.tmp"))
    finally:
        kernel.CloseHandle(handle)
    print("PASS: failing native replacement preserves original and cleans temporary file")

    attributes = kernel.GetFileAttributesW(str(path.absolute()))
    check(kernel.SetFileAttributesW(str(path.absolute()), attributes | 1))
    try:
        finish(start("failure"))
        assert read_shared(path) == original
        assert not list(root.glob("*.tmp"))
    finally:
        check(kernel.SetFileAttributesW(str(path.absolute()), attributes))
    print("PASS: readonly replacement failure preserves original and removes readonly temporary")

    finish(start("cleanup_failure"))
    assert read_shared(path) == original
    assert not list(root.glob("*.tmp"))
    print("PASS: cleanup failure is returned explicitly, not ignored")

    process = start("partial")
    assert process.stdout.readline().strip() == "PARTIAL"
    partials = list(root.glob("*.tmp"))
    assert len(partials) == 1 and partials[0].stat().st_size == 1024
    assert_private(partials[0], reader)
    assert security_descriptor(partials[0]) == original_security, (
        security_descriptor(partials[0]), original_security,
    )
    kill_owner(process)
    finish(process, input="finish\n")
    assert read_shared(path) == original
    assert_private(partials[0], reader)
    assert security_descriptor(partials[0]) == original_security, (
        security_descriptor(partials[0]), original_security,
    )
    partials[0].unlink()
    print("PASS: partial and owner-interrupted temporary deny the same restricted reader")

    for mode in ("timeout", "owner", "port"):
        path.write_bytes(original)
        started = time.monotonic()
        process = start(mode)
        marker, helper = active_helper(process)
        try:
            if mode == "owner":
                kill_owner(process)  # Kill only the Erlang owner, not the VM or its children.
            elif mode == "port":
                closed = time.monotonic()
                command(process, "close-port")
                finish(process)
                assert time.monotonic() - closed < 20
            else:
                finish(process)
                assert time.monotonic() - started < 8
            assert kernel.WaitForSingleObject(helper, 5000) == 0
            assert not list(root.glob("*.tmp"))
            assert read_shared(path) == original
            time.sleep(6.5)
            assert read_shared(path) == original
            if mode == "owner":
                finish(process, input="finish\n")
        finally:
            kernel.CloseHandle(helper)
            marker.unlink()
        print(f"PASS: {mode} reaps exact helper before cleanup; no delayed replacement")

    path.write_bytes(original)
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
        output = finish(start("loop", complete.decode("utf-8")))
        assert "REPLACED" in output
    finally:
        stopped.set()
        watcher.join()
    assert not failures, failures
    assert observations[0] > 0
    print(f"PASS: {observations[0]} concurrent old-or-complete reads; destination never absent")
finally:
    if "reader" in globals():
        kernel.CloseHandle(reader)
    for artifact in root.iterdir():
        artifact.unlink()
    root.rmdir()
