---
layout: ../../layouts/DocsLayout.astro
title: sbom
description: Create a CycloneDX 1.6 JSON SBOM from your locked dependency tree. Does not evaluate licence policy.
---

`sbom` creates a [CycloneDX 1.6][cyclonedx] document that describes all locked
dependencies. It does **not** evaluate licence policy.

```sh
licence_audit sbom                     # pretty JSON to stdout
licence_audit sbom --output=sbom.json  # pretty JSON to a file
licence_audit sbom --offline           # skip Hex fetch, omit licence fields
licence_audit sbom --reproducible      # reproducible output
licence_audit sbom --vulns             # embed OSV vulnerabilities
licence_audit sbom --license-text      # embed canonical SPDX licence text
```

## Document contents

For each locked dependency, `sbom` creates a component with this information:
a package URL, a SHA-256 hash for Hex packages, the package description,
declared licences, and external references. The package URL is `pkg:hex/...`
for Hex and `pkg:github/owner/repo@<commit>` for GitHub git dependencies. The
external references can identify the tarball, source, home page, and
documentation. [Project configuration](/docs/configuration#discovery) supplies
information for the root component. A `dependencies` graph represents the
dependency tree.

For a Git dependency with a manifest `path`, the purl includes the encoded
package subpath, for example
`pkg:github/example/beryl@<commit>#packages/beryl_protocol`.
`--reproducible` reads `gleam.toml` only from that package subdirectory.
Missing package metadata is an error; repository-root metadata is not a fallback.
The immutable metadata cache key includes the package path.

Each licence has the property `acknowledgement: "declared"` because the data
comes from package metadata, not a source scan. If a package declares multiple
licences, `sbom` creates one entry for each licence. Hex does not specify an
`AND` or `OR` relationship, so `sbom` does not create an SPDX expression.

These are **declared** licences, not **concluded** licences from a source scan.
`licence_audit` does not inspect dependency source to conclude licences or
extract copyright holders. Use a source scanner when you need that evidence.

## Embedded licence text

`--license-text` adds canonical SPDX License List text to recognised licence
IDs on dependencies and the root component:

```json
{"license":{"id":"Apache-2.0","text":{"contentType":"text/plain","content":"..."},"acknowledgement":"declared"}}
```

The text comes from the same fixed SPDX revision and shared cache as
[`notices`](/docs/notices), not from package source. It is reference text,
not package-specific copyright or attribution evidence. Default output does
not include this text.

IDs match without regard to case. Each declared ID receives its own text.
Expressions with `AND`, `OR`, or `WITH`, custom `LicenseRef-*` references,
and unknown names remain `name` entries without text. The command does not
select an expression alternative or combine texts.

This flag requires network access on a cache miss and **conflicts with
`--offline`**. It works with `--reproducible` because the SPDX revision is
fixed. Use `--no-cache` to bypass the text cache. `--cache-path` relocates the
metadata cache only; use `XDG_CACHE_HOME` to relocate both caches.

A failed text request, invalid SPDX response, or missing text for a recognised
ID exits `2` before writing the SBOM. Optional package metadata enrichment
remains unchanged: a dependency without licence metadata has no licence text.

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
locked archives do not expire. Use `--cache-path=DIR` to override the cache
directory, or `--no-cache` to fetch the metadata again.

## Flags

Both stdout and `--output=PATH` use pretty-printed JSON. When writing a file,
stdout stays empty.

<!-- cli-reference -->
Generate a CycloneDX 1.6 JSON SBOM from manifest.toml. Does not evaluate licence policy. Includes all dependencies with their CycloneDX scope. JSON output stays plain in every color mode.

**Usage:**

```
licence_audit sbom [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-path` | `STRING` |  | Override the licence metadata cache directory |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--license-text` | `BOOL` | `false` | Embed canonical SPDX text for recognised licence IDs (requires network on cache miss; conflicts with --offline) |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--offline` | `BOOL` | `false` | Skip Hex metadata fetch; with --reproducible, skip all dependency enrichment including Git |
| `--output` | `STRING` |  | Write SBOM to PATH instead of stdout |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--reproducible` | `BOOL` | `false` | Reproducible output from locked package archives (unless --offline): serialNumber is a content hash and timestamp comes from SOURCE_DATE_EPOCH (default 1970-01-01T00:00:00Z) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
| `--vulns` | `BOOL` | `false` | Query OSV.dev and embed a CycloneDX vulnerabilities array (requires network; conflicts with --offline and --reproducible) |
<!-- cli-referencestop -->

[cyclonedx]: https://cyclonedx.org/
[dt]: https://dependencytrack.org/
[sde]: https://reproducible-builds.org/docs/source-date-epoch/
