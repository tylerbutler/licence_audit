---
layout: ../../layouts/DocsLayout.astro
title: sbom
description: Create a CycloneDX 1.6 JSON SBOM from your locked dependency tree. Does not evaluate licence policy.
---

`sbom` creates a [CycloneDX 1.6][cyclonedx] document that describes all locked
dependencies. It does **not** evaluate licence policy.

```sh
licence_audit sbom                     # pretty JSON to stdout
licence_audit sbom --output=sbom.json  # compact JSON to a file
licence_audit sbom --offline           # skip Hex fetch, omit licence fields
licence_audit sbom --reproducible      # reproducible output
licence_audit sbom --vulns             # embed OSV vulnerabilities
```

## Document contents

For each locked dependency, `sbom` creates a component with this information:
a package URL, a SHA-256 hash for Hex packages, the package description,
declared licences, and external references. The package URL is `pkg:hex/...`
for Hex and `pkg:github/owner/repo@<commit>` for GitHub git dependencies. The
external references can identify the tarball, source, home page, and
documentation. Data from `gleam.toml` supplies information for the root
component. A `dependencies` graph represents the dependency tree.

Each licence has the property `acknowledgement: "declared"` because the data
comes from package metadata, not a source scan. If a package declares multiple
licences, `sbom` creates one entry for each licence. Hex does not specify an
`AND` or `OR` relationship, so `sbom` does not create an SPDX expression.

## Supported sources

`sbom` supports only `hex` and GitHub `git` sources. It **fails** on a
dependency source that it cannot convert to a valid purl. Unsupported sources
include path dependencies and non-GitHub git dependencies. `--offline` skips
licence requests but continues to validate purls. The [`vulns`](/docs/vulns)
command has different behavior: it identifies and skips unsupported sources.

## Completion and optional enrichment

Default `sbom` generation exits `0` when optional Hex or local Git dependency
metadata is unavailable. It warns and omits the unavailable fields.
`--offline` intentionally skips Hex enrichment. This differs from a licence
audit, where unavailable package metadata makes the report incomplete (exit `2`).

These items are required. If one fails, the command exits `2`:

- root metadata,
- valid purls for supported sources,
- SBOM generation and file writes.

How `--reproducible` and `--offline` combine:

| Flags | Dependency metadata | If metadata is unavailable |
|---|---|---|
| `--reproducible` | Read from the locked source archives. | Exit `2`. |
| `--reproducible --offline` | None. All enrichment, including local Git metadata, is skipped. Licence fields are omitted. | Not applicable. Can exit `0`. |

## Embedded vulnerabilities

`--vulns` queries OSV.dev and adds the results to the CycloneDX
`vulnerabilities` array. Each advisory has an `id`, an `OSV` source link,
ratings, and an `affects` list. The list refers to affected components by
`bom-ref` or purl. Tools such as [Dependency-Track][dt] can read this
VEX-style document. Advisory data changes over time, so you cannot use
`--vulns` with `--offline` or `--reproducible`.

An OSV batch request failure exits `2`. An individual advisory-detail failure
warns and retains its ID with unknown severity; generation still exits `0`.
In contrast, `check --vulns` exits `2` when details are unavailable because it
cannot evaluate the severity gate.

## Reproducible output

By default, `sbom` uses a random `serialNumber` and the current time for
`timestamp`. The output from two runs is different. With
`--reproducible` without `--offline`, the command reads Hex metadata from each
checksum-verified package archive and Git metadata from the archive at the
locked commit. It omits mutable Hex publisher data, uses a content hash for
`serialNumber`, and gets the timestamp from [`SOURCE_DATE_EPOCH`][sde], or uses the Unix epoch if
the variable is not set. The same project files, lockfile, tool version,
options, and timestamp produce byte-identical output.

The command reuses the shared [metadata cache](/docs/#caching). Entries from
locked archives do not expire. Use `--cache-path=PATH` to override the cache
location, or `--no-cache` to fetch the metadata again.

## Flags

| Flag | What it does |
|---|---|
| `--output` | Write the SBOM to `PATH` (compact) instead of stdout (pretty). |
| `--offline` | Skip Hex metadata; with `--reproducible`, skip all dependency enrichment, including Git. |
| `--reproducible` | Use locked package archives (unless `--offline`), a content hash, and `SOURCE_DATE_EPOCH` for reproducible output. |
| `--vulns` | Query OSV.dev and embed a `vulnerabilities` array. Conflicts with `--offline` and `--reproducible`. |
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--cache-path` | Override the licence metadata cache location. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |

[cyclonedx]: https://cyclonedx.org/
[dt]: https://dependencytrack.org/
[sde]: https://reproducible-builds.org/docs/source-date-epoch/
