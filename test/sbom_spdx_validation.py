# /// script
# requires-python = ">=3.10"
# dependencies = ["jsonschema==4.23.0", "spdx-tools==0.8.5"]
# ///
"""Validate SPDX output against the official schema and SPDX semantic rules."""

import json
import os
from pathlib import Path
import subprocess
import urllib.request

import jsonschema
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document


# SPDX specification v2.3, immutable source; fetched unmodified for validation.
SCHEMA_URL = (
    "https://raw.githubusercontent.com/spdx/spdx-spec/"
    "aadf3b0b8dbbabdb4d880b0fc714255fea436ff7/schemas/spdx-schema.json"
)
EXECUTABLE = str(Path("licence_audit").resolve())
ENV = {**os.environ, "SOURCE_DATE_EPOCH": "1234567890"}


def cli(*args, expected=0):
    result = subprocess.run(
        [EXECUTABLE, "sbom", "--no-cache", "--quiet", *args],
        capture_output=True,
        text=True,
        env=ENV,
        check=False,
    )
    assert result.returncode == expected, result.stderr + result.stdout
    return result.stdout


def validate(path, schema):
    document = json.loads(path.read_text())
    jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        document
    )
    messages = validate_full_spdx_document(parse_file(str(path)))
    assert not messages, "\n".join(str(message) for message in messages)
    ids = [document["SPDXID"], *(p["SPDXID"] for p in document["packages"])]
    assert len(ids) == len(set(ids)), "Duplicate SPDX identifiers"
    for relationship in document["relationships"]:
        assert relationship["spdxElementId"] in ids
        assert relationship["relatedSpdxElement"] in ids
    print(f"{path}: official SPDX 2.3 schema and semantic validation passed")
    return document


def main():
    with urllib.request.urlopen(SCHEMA_URL, timeout=30) as response:
        schema = json.load(response)

    fixture = validate(Path("build/spdx-test.json"), schema)
    root = fixture["packages"][0]
    assert root["licenseDeclared"] == "NOASSERTION"
    assert 'LicenseRef-Private \\"custom\\"' in root["licenseComments"]
    assert "hasExtractedLicensingInfos" not in fixture
    validate(Path("build/spdx-empty-test.json"), schema)

    args = ("--format=spdx-json", "--offline", "--reproducible")
    path = Path("build/spdx-cli.json")
    assert cli(*args, f"--output={path}") == ""
    first_bytes = path.read_bytes()
    first = validate(path, schema)
    assert first["creationInfo"]["created"] == "2009-02-13T23:31:30Z"
    assert cli(*args, f"--output={path}") == ""
    assert path.read_bytes() == first_bytes, "Reproducible CLI output changed"
    assert json.loads(cli(*args)) == first, "stdout and file output disagree"

    random_args = ("--format=spdx-json", "--offline")
    cli(*random_args, "--output=build/spdx-random.json")
    random = validate(Path("build/spdx-random.json"), schema)
    assert random["documentNamespace"] != first["documentNamespace"]
    assert (
        json.loads(cli(*random_args))["documentNamespace"]
        != random["documentNamespace"]
    )

    default = cli("--offline", "--reproducible")
    explicit = cli("--offline", "--reproducible", "--format=cyclonedx-json")
    assert default == explicit
    assert json.loads(default)["bomFormat"] == "CycloneDX"
    cli("--format=spdx-json", "--vulns", expected=1)
    cli("--format=invalid", expected=1)
    print("CLI format selection, output, usage errors and reproducibility passed")


if __name__ == "__main__":
    main()
