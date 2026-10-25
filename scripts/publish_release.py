"""Publish only after required build and target-runtime jobs pass."""

import argparse
import json
from pathlib import Path
import subprocess


def publish(tag, repository, directory, template, changelog, build_result, runtime_result):
    if build_result != "success" or runtime_result != "success":
        raise RuntimeError("Required build and native runtime checks must pass")

    def gh(*arguments, check=True):
        return subprocess.run(
            ["gh", "release", *arguments], check=check, capture_output=True, text=True,
        )

    existing = gh("view", tag, "--json", "body,isDraft", check=False)
    if existing.returncode == 0:
        release = json.loads(existing.stdout)
    else:
        heading = f"## {tag} - "
        sections = changelog.read_text().splitlines()
        start = next(index for index, line in enumerate(sections) if line.startswith(heading))
        end = next(
            (index for index in range(start + 1, len(sections)) if sections[index].startswith("## ")),
            len(sections),
        )
        body = "\n".join(sections[start + 1:end]).strip()
        gh("create", tag, "--draft", "--verify-tag", "--title", tag, "--notes", body)
        release = {"body": body, "isDraft": True}

    assets = sorted(str(path) for path in directory.iterdir() if path.is_file())
    if not assets:
        raise RuntimeError("No staged release artifacts")
    gh("upload", tag, *assets, "--clobber")
    body = release["body"]
    if "<!-- install-instructions -->" not in body:
        install = template.read_text().replace("${REPO}", repository).replace("${REF_NAME}", tag)
        body = f"{body}\n\n{install}"
        gh("edit", tag, "--notes", body)
    if release["isDraft"]:
        gh("edit", tag, "--draft=false")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--build-result", required=True)
    parser.add_argument("--runtime-result", required=True)
    arguments = parser.parse_args()
    publish(
        arguments.tag, arguments.repository, arguments.directory,
        arguments.template, arguments.changelog,
        arguments.build_result, arguments.runtime_result,
    )
