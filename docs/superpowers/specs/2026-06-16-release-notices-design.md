# Release licence notices design

## Research summary

The closest npm analogue is `generate-license-file`. It generates a
release-ready text file, usually `third-party-licenses.txt`, that contains the
full licence text for production dependencies. It supports an input
`package.json`, an output path, overwrite control, line-ending control, and
configuration for appended text, package exclusions, and replacement licence
text.

Adjacent npm tools solve different problems. `license-checker` and
`license-report` report declared licence identifiers, metadata, or tables. They
help with audits, but they do not primarily create a bundled full-text licence
file for release distribution. `licence_audit notices` should follow the
`generate-license-file` model, not the summary-report model.

## Goal

Add a `licence_audit notices` subcommand that creates a release-ready
third-party licence text file for locked Gleam dependencies. The command emits
the actual licence and notice files shipped by dependencies, not canonical SPDX
text inferred from identifiers.

## Non-goals

- Do not change `licence_audit sbom`; it remains the CycloneDX JSON command.
- Do not enforce the configured allow/deny policy.
- Do not deduplicate common licence text across packages.
- Do not synthesize canonical licence text from SPDX IDs.
- Do not add config-file support for exclusions, appendices, or replacement text
  in the first version.

## Command surface

`licence_audit notices` reads `manifest.toml`, selects dependencies, extracts
licence material, and prints plain UTF-8 text.

```sh
licence_audit notices
licence_audit notices --output=THIRD_PARTY_LICENSES.txt
licence_audit notices --include-dev
licence_audit notices --manifest=other/manifest.toml
```

Flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--manifest=PATH` | `manifest.toml` | Read the lockfile from `PATH`. |
| `--output=PATH` | stdout | Write the generated notice file to `PATH`. |
| `--include-dev` | `false` | Include dev-only dependencies as well as production dependencies. |
| `--quiet` | `false` | Suppress progress output. |
| `--verbose` | `false` | Show per-package progress. |

The command defaults to production dependencies because release artifacts
usually ship runtime code, not development tooling. `--include-dev` includes the
full locked dependency set when a project wants a complete development notice
file.

`--output` overwrites existing files. This matches `sbom --output` and keeps the
command suitable for repeatable release scripts.

## Architecture

The feature adds one new action path and two focused support modules.

- `cli.gleam` adds `NoticesOptions` and `RunNotices`.
- `src/licence_audit.gleam` adds `run_notices_options` and dispatcher plumbing.
- `notices.gleam` selects packages, finds licence files, builds `NoticeEntry`
  values, and renders the final text.
- `source_archive.gleam` reads tar/gzip archives through a small Erlang FFI
  module that wraps OTP archive functions.
- Existing `manifest` scope helpers determine production versus dev packages.
- Existing progress reporting records the command phase, package count, and
  per-package details.

The implementation reuses existing manifest parsing and scope classification
instead of adding a second dependency graph model.

## Data flow

The command follows this pipeline:

1. Load `manifest.toml` as an SBOM-style manifest so each entry keeps its
   provenance.
2. Compute production/dev scope from `gleam.toml` and the existing dependency
   graph logic.
3. Select production dependencies unless `--include-dev` is set.
4. Fetch or read source content for each selected dependency.
5. Verify checksums where the lockfile provides one.
6. Extract standard licence and notice files.
7. Fail if any selected dependency lacks licence text.
8. Render package sections sorted by package name and version.
9. Print to stdout or write `--output`.

## Source handling

Hex packages use `https://repo.hex.pm/tarballs/<name>-<version>.tar`. The
command verifies the downloaded tarball against the lockfile's
`outer_checksum`. It then extracts `contents.tar.gz` and scans that content
archive for licence files.

GitHub git dependencies use the same GitHub URL parser already used for SBOM
purls. The command fetches
`https://codeload.github.com/<owner>/<repo>/tar.gz/<commit>` and scans the
archive for licence files. It fails for non-GitHub git dependencies because the
lockfile does not provide a generic archive URL or checksum.

Path dependencies read the local path from the lockfile and scan that directory.
The path resolves relative to the project root that contains the manifest.

Unknown or unsupported sources fail with a clear diagnostic. A release notice
file must not silently omit a dependency.

## Licence file detection

The scanner matches root-level licence material first. Accepted base names are:

- `LICENSE`
- `LICENCE`
- `COPYING`
- `NOTICE`

Accepted suffixes are no suffix, `.txt`, `.md`, `.rst`, and `.adoc`. Matching is
case-insensitive. If no root-level file matches, the scanner falls back to the
same names anywhere in the package tree, sorted by path, so packages that nest
licence material remain usable.

When a package contains several matches, the command includes all of them in
stable path order. `NOTICE` files matter even when a package also ships
`LICENSE`, so the scanner must not stop after the first match.

## Output format

The output is deterministic plain text with LF line endings. It starts with a
short generated header, then one section per dependency:

```text
Third-party licences
Generated by licence_audit notices from manifest.toml.

================================================================================
gleam_stdlib 1.0.3
Source: hex
Declared licences: Apache-2.0
Files: LICENCE
--------------------------------------------------------------------------------
<exact LICENCE text>
```

For GitHub and path dependencies, `Source` includes the repository and commit or
the local path. If a dependency has no declared licence metadata, the renderer
prints `Declared licences: unknown`; it still includes extracted licence text.

The renderer does not deduplicate text across packages. Copyright lines,
exceptions, and package-specific notices can differ even when packages declare
the same SPDX identifier.

## Error handling

The command exits `0` after it writes a complete notice file. It exits `2` for
input, network, archive, checksum, source, missing-text, or output-write
failures.

When several packages lack licence text, the command reports all of them in one
diagnostic. It continues collecting after per-package missing-text errors, but
it stops on global errors such as an unreadable manifest or an unwritable output
path.

Checksum mismatches are hard failures. A release notice file must reflect the
exact locked artifact.

## Progress behavior

Normal progress reports the high-level phase and package count. Verbose progress
adds per-package fetch and extraction details. Quiet mode suppresses progress.
As with existing commands, user-facing artifact output appears before deferred
progress messages.

## Tests

Unit and integration tests cover:

- CLI parsing for `notices`, `--output`, `--include-dev`, `--manifest`,
  `--quiet`, and `--verbose`.
- Production-only default selection and `--include-dev` selection.
- Hex tarball checksum verification.
- Archive extraction for a fixture tarball with `contents.tar.gz`.
- GitHub archive extraction through an injected fetcher.
- Path dependency scanning.
- Missing licence text aggregation.
- Unsupported source failures.
- Multiple licence files in one dependency.
- Case-insensitive filename matching and accepted suffixes.
- Deterministic package and file ordering.
- Output-file writing and stdout rendering.

Tests inject fetchers and use fixture archives. They must not hit Hex.pm or
GitHub.

## Documentation

Add `docs/notices.md` and update the README command list. The docs explain that
`notices` creates the release text artifact, while `sbom` creates the
machine-readable CycloneDX artifact. The docs mention `generate-license-file` as
the npm analogue and state that `notices` uses the licence files shipped inside
each locked dependency.

## Future extensions

Later versions can add appendices, package exclusions, replacement text,
line-ending control, and an optional cache for downloaded source archives. These
extensions should not block the first version.
