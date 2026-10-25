#!/usr/bin/env python3
"""Run the same release checks on the target host, not a cross-build host."""

import argparse
import errno
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid


def validate_output(name, output, status, expected=0):
    failures = (
        r"noproc|Failed to eval|Runtime terminating|Crash dump|"
        r"Vulnerability check incomplete:|\(details unavailable\)|"
        r"Picker failed to read terminal input"
    )
    warnings = [
        line for line in output.splitlines()
        if re.search(r"WARN\s+\|", line)
        and not re.search(r"IPv6 .*; using IPv4 for the remaining Hex and OSV requests", line)
        and not (
            name == "update-redirected"
            and line.endswith("The update picker requires an interactive terminal on stdin and stdout")
        )
        and not (name == "update-cancel" and line.endswith("Update cancelled"))
    ]
    if re.search(failures, output) or warnings:
        raise AssertionError(f"{name}: runtime failure or incomplete report\n{output}")
    if name == "check" and status == 1:
        assert "Vulnerability check failed: one or more advisories" in output, output
    else:
        assert status == expected, f"{name}: unexpected exit {status}\n{output}"


def interactive(binary, work, environment, keys):
    """Use a real Unix PTY or Windows ConPTY; redirected stdin is not enough."""
    if os.name == "nt":
        from winpty import Backend, PtyProcess

        child = PtyProcess.spawn(
            [str(binary), "update", "--color=never"],
            cwd=str(work), env=environment, backend=Backend.ConPTY,
        )
        chunks = queue.Queue()

        def read_console():
            try:
                while True:
                    text = child.read(4096)
                    if not text:
                        break
                    chunks.put(text)
            except EOFError:
                pass
            finally:
                chunks.put(None)

        threading.Thread(target=read_console, daemon=True).start()
        read = lambda: chunks.get(timeout=0.2)
        write = child.write
        alive = child.isalive
        finish = lambda: child.exitstatus
        stop = lambda: child.terminate(force=True)
    else:
        import fcntl
        import pty
        import select
        import signal
        import struct
        import termios

        pid, terminal = pty.fork()
        if pid == 0:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            os.chdir(work)
            os.execve(binary, [str(binary), "update", "--color=never"], environment)

        def read():
            if not select.select([terminal], [], [], 0.2)[0]:
                raise queue.Empty
            try:
                return os.read(terminal, 4096).decode("utf-8", errors="replace")
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                return None

        write = lambda text: os.write(terminal, text.encode())
        alive = lambda: True  # EOF is followed by waitpid below.
        finish = lambda: os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
        stop = lambda: os.kill(pid, signal.SIGKILL)

    output = ""
    sent = False
    completed = False
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                chunk = read()
            except queue.Empty:
                if not alive():
                    completed = True
                    break
                continue
            if not chunk:
                completed = True
                break
            output += chunk
            if not sent and "esc cancel" in output:
                write(keys)
                sent = True
        assert completed and sent, f"update: picker did not complete\n{output}"
        return output, finish()
    finally:
        if not completed:
            stop()
        if os.name != "nt":
            if not completed:
                os.waitpid(pid, 0)
            os.close(terminal)


def smoke(binary, work, expected_version):
    fixtures = Path(__file__).resolve().parent / "fixtures" / "native_http"
    for name in ("gleam.toml", "manifest.toml"):
        shutil.copyfile(fixtures / name, work / name)
    for name in ("home", "empty-path"):
        (work / name).mkdir()
    environment = {
        key: value for key, value in os.environ.items()
        if key.upper() in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")
    }
    environment.update(
        HOME=str(work / "home"), USERPROFILE=str(work / "home"),
        APPDATA=str(work / "home"), LOCALAPPDATA=str(work / "home"),
        XDG_CACHE_HOME=str(work / "home" / ".cache"),
        PATH=str(work / "empty-path"), TERM="xterm-256color",
        TMPDIR=str(work), TMP=str(work), TEMP=str(work),
        ERL_CRASH_DUMP=os.devnull, ERL_FLAGS="+S 2:2 +SDcpu 1 +SDio 1",
    )

    def run(name, *arguments, expected=0):
        result = subprocess.run(
            [str(binary), *arguments], cwd=work, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60, encoding="utf-8", errors="replace",
        )
        (work / f"{name}.log").write_text(result.stdout, encoding="utf-8")
        validate_output(name, result.stdout, result.returncode, expected)
        return result.stdout

    assert "USAGE:" in run("help", "--help")
    version = run("version", "--version").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+[^\s]*", version), version
    if expected_version:
        assert version == expected_version.removeprefix("v"), version

    for name, cache_event in (
        ("report-cold", "Cache miss for"),
        ("report-warm", "Cache hit for"),
    ):
        output = run(name, "--verbose", "--color=never")
        assert re.search(r"gleam_stdlib\s+1\.0\.5\s+Apache-2\.0", output), output
        assert "Skipped non-Hex packages: 0" in output, output
        assert f"{cache_event} gleam_stdlib@1.0.5" in output, output

    output = run("vulns", "vulns", "--color=never")
    assert re.search(
        r"Checked 1 packages: (0 with vulnerabilities, 1 clean|1 with vulnerabilities, 0 clean)\.",
        output,
    ), output
    output = run("check", "check", "--vulns", "--color=never")
    assert re.search(r"gleam_stdlib\s+1\.0\.5\s+Apache-2\.0.*allowed", output), output
    assert re.search(r"No known vulnerabilities reported by OSV.dev.|advisory/advisories at or above", output), output
    run("sbom", "sbom", "--reproducible", "--offline", "--output=smoke-sbom.json")
    assert "pkg:hex/gleam_stdlib@1.0.5" in (work / "smoke-sbom.json").read_text()

    output = run("update-redirected", "update", "--color=never", expected=1)
    assert "requires an interactive terminal" in output, output
    policy = work / "gleam.toml"
    for name, keys, expected in (("deny", "d\r", 0), ("allow", "a\r", 0), ("cancel", "q", 130)):
        before = policy.read_bytes()
        output, status = interactive(binary, work, environment, keys)
        (work / f"update-{name}.log").write_text(output, encoding="utf-8")
        # Cancellation emits an expected warning.
        if name == "cancel":
            validate_output("update-cancel", output, status, expected)
            assert "Update cancelled" in output, output
            assert policy.read_bytes() == before
        else:
            validate_output("update", output, status)
            setting = "deny" if name == "deny" else "allow"
            assert re.search(rf'{setting}\s*=\s*\["Apache-2\.0"\]', policy.read_text()), policy.read_text()
    print("Native release smoke passed: startup, HTTPS, cold/warm cache, update PTY.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path)
    source.add_argument("--binary", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--version")
    arguments = parser.parse_args()
    work = (Path("build") / f"native-smoke-{uuid.uuid4().hex}").resolve()
    work.mkdir(parents=True)
    try:
        if arguments.archive:
            hosts = {
                "x86_64-linux-glibc": ("Linux", "x86_64"),
                "aarch64-linux-glibc": ("Linux", "aarch64"),
                "x86_64-macos": ("Darwin", "x86_64"),
                "aarch64-macos": ("Darwin", "arm64"),
                "x86_64-windows": ("Windows", "AMD64"),
            }
            assert hosts[arguments.target] == (platform.system(), platform.machine()), "Wrong runtime host"
            shutil.unpack_archive(arguments.archive.resolve(), work / "install")
            name = "licence_audit.exe" if os.name == "nt" else "licence_audit"
            binaries = list((work / "install").rglob(name))
            assert len(binaries) == 1, binaries
            binary = binaries[0]
            binary.chmod(0o755)
        else:
            binary = arguments.binary.resolve()
        smoke(binary, work, arguments.version)
    except BaseException:
        for log in sorted(work.glob("*.log")):
            print(f"\n=== {log.name} ===\n{log.read_text(encoding='utf-8')}")
        raise
    finally:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
