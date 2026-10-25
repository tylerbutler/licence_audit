"""Verify program-scoped Windows isolation and cleanup without touching other clients."""

import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import uuid

from native_release_smoke import windows_program_isolation


def main():
    work = (Path("build") / f"windows-network-probe-{uuid.uuid4().hex}").resolve()
    work.mkdir(parents=True)
    try:
        probe = work / "curl.exe"
        shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "curl.exe", probe)
        command = [
            str(probe), "--fail", "--silent", "--show-error", "--max-time", "10",
            "https://hex.pm/api/packages/gleam_stdlib",
        ]
        subprocess.run(command, check=True, capture_output=True, timeout=15)
        group = os.environ["SMOKE_FIREWALL_GROUP"]
        try:
            with windows_program_isolation([probe], group):
                with urllib.request.urlopen(command[-1], timeout=15) as response:
                    assert response.status == 200
                blocked = subprocess.run(command, capture_output=True, timeout=15)
                assert blocked.returncode in (6, 7, 28), blocked.stderr
                raise RuntimeError("injected failure to check firewall cleanup")
        except RuntimeError as error:
            if str(error) != "injected failure to check firewall cleanup":
                raise
        subprocess.run(command, check=True, capture_output=True, timeout=15)
        print("Scoped firewall passed: copied child blocked, unrelated HTTPS usable, cleanup after failure.")
    finally:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
