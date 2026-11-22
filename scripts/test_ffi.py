"""Compile native test helpers outside Gleam's production source scan."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SOURCES = sorted((ROOT / "native/test").rglob("*.erl"))
if not SOURCES:
    raise SystemExit("No native test helpers found under native/test")

subprocess.run(["gleam", "build", "--target", "erlang"], cwd=ROOT, check=True)
subprocess.run(
    [
        "erlc", "-o", str(ROOT / "build/dev/erlang/licence_audit/ebin"),
        *(str(path) for path in SOURCES),
    ],
    cwd=ROOT,
    check=True,
)
