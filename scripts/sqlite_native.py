"""Stage esqlite's compiled application beside an exported escript."""

import argparse
from pathlib import Path
import shutil


def stage(source, destination):
    source = Path(source)
    destination = Path(destination)
    beams = sorted((source / "ebin").glob("*.beam"))
    apps = sorted((source / "ebin").glob("*.app"))
    libraries = [
        path for path in (source / "priv").rglob("*")
        if path.is_file() and path.suffix in (".so", ".dll", ".dylib")
    ]
    if not beams or not apps or not libraries:
        raise ValueError(f"Compiled esqlite application is incomplete: {source}")
    source_root, destination_root = source.resolve(), destination.resolve()
    if (source_root == destination_root or source_root in destination_root.parents
            or destination_root in source_root.parents):
        raise ValueError("The staging destination must be outside the compiled application")
    if destination.exists():
        shutil.rmtree(destination)
    (destination / "ebin").mkdir(parents=True)
    for path in beams + apps:
        shutil.copy2(path, destination / "ebin" / path.name)
    for path in libraries:
        relative = path.relative_to(source)
        (destination / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination / relative)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("build/prod/erlang/esqlite"))
    parser.add_argument("--destination", type=Path, default=Path("sqlite_native/esqlite"))
    args = parser.parse_args()
    try:
        stage(args.source, args.destination)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Cannot stage SQLite native application: {error}\n")


if __name__ == "__main__":
    main()
