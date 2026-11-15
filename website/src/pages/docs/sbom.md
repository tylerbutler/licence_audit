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
licence_audit sbom --offline           # skip Hex fetch; retain local metadata
licence_audit sbom --reproducible      # reproducible output
licence_audit sbom --vulns             # embed OSV vulnerabilities
licence_audit sbom --license-text      # embed canonical SPDX licence text
```

## Document contents

For each locked dependency, `sbom` creates a component with this information:
a package URL for published sources, a SHA-256 hash for Hex packages, the package description,
declared licences, and external references. The package URL is `pkg:hex/...`
for Hex and `pkg:github/owner/repo@<commit>` for GitHub git dependencies. The
external references can identify the tarball, source, home page, and
documentation. [Project configuration](/docs/configuration#discovery) supplies
information for the root component. A `dependencies` graph represents the
dependency tree.

The tool vendor identifies `licence_audit`'s publisher. The document omits
`metadata.authors` because the tool does not know who created the BOM.

For a Git dependency with a manifest `path`, the purl includes the encoded
package subpath, for example
`pkg:github/example/beryl@<commit>#packages/beryl_protocol`.
`--reproducible` reads `gleam.toml` only from that package subdirectory.
Missing package metadata is an error; repository-root metadata is not a fallback.
The immutable metadata cache key includes the package path.

All locked dependencies remain in the document. Components reachable from
`[dependencies]` in the project's `gleam.toml` have scope `required`; development-only
components have scope `optional`. A valid file without `[dependencies]`, or
with an empty table, makes all dependency components `optional`. Invalid TOML
or a `dependencies` value that is not a table causes exit code `2`.

Each licence choice has the property `acknowledgement: "declared"` because the
data comes from package metadata, not a source scan. A single valid compound
SPDX declaration with `AND`, `OR`, or `WITH` becomes an `expression` choice.
Plain recognised IDs remain `license.id` entries. Custom names and malformed
expressions remain `license.name` entries.

If a package declares multiple licences, `sbom` creates one independent
`license` entry for each declaration, even if an entry contains an expression.
Hex does not specify an `AND` or `OR` relationship between entries, so `sbom`
does not combine them. Expression parsing is limited to 64 KiB, 1024 tokens,
and 64 nested parentheses; declarations above these limits remain names.

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
Expression choices and `name` entries have no embedded text. Custom
`LicenseRef-*` references and unknown names remain names. The command does
not select an expression alternative or combine texts.

This flag requires network access on a cache miss and **conflicts with
`--offline`**. It works with `--reproducible` because the SPDX revision is
fixed. Use `--no-cache` to bypass the caches without deleting entries.
`--cache-dir=DIR` selects the shared application root, including the
`spdx-v1/` text cache and `hex-v2/` metadata cache.

A failed text request, invalid SPDX response, or missing text for a recognised
ID exits `2` before writing the SBOM. Optional package metadata enrichment
remains unchanged: a dependency without licence metadata has no licence text.

## Supported sources

`sbom` supports `hex`, GitHub `git`, and local path sources (`source = "local"`
or the `"path"` alias). Non-GitHub git and unknown sources still fail.
`--offline` does not bypass source or local metadata validation.
The [`vulns`](/docs/vulns) command skips local sources because they have no
published package URL to query in OSV.

### Local workspace components

Local components have `type: "library"`, a locked version, declared metadata,
and the same scope rules as external components. Their `bom-ref` is
`local:<deterministic UUID>`, derived from the package name, version, and
normalized path relative to the manifest directory. These properties identify
the local source:

```json
[
  {"name": "licence_audit:source", "value": "local"},
  {"name": "licence_audit:local_path", "value": "../local_package"}
]
```

The reference is a document identity, not a source-content checksum or a
globally immutable package identity. Local components have no purl, archive
hash, registry supplier, tarball reference, or signature. A declared repository
is a source link only; it does not claim a Hex publication.

Lockfile paths resolve relative to the directory containing `--manifest`.
Nested local dependency declarations resolve relative to the declaring
package's directory. Parent-relative paths are supported. Absolute paths must
be on the same filesystem volume as the manifest and are emitted as relative
paths. Normalization is lexical: `.` and `..` are collapsed before file access.
Symlink aliases are not canonicalized; declarations must use the same
normalized path as the lockfile.

Every local package must have a readable, valid `gleam.toml`. Its name and
semantic version must match the lockfile. Production dependency names must
match locked requirements, and nested local paths must match locked targets.
The root project's local declarations are also checked against locked targets.
Missing paths or metadata, malformed metadata fields, stale identities or
edges, duplicate locked names, and cycles involving local components exit `2`
before output is written. Run `gleam deps download` to refresh a stale lockfile.

The root lockfile supplies the complete graph. No member manifest is required,
and workspace members' own development dependencies are not added.
Local description, licence, link, and repository metadata is read on every
run, including `--reproducible --offline`; it is not cached.

## Completion and optional enrichment

Default `sbom` generation exits `0` when optional Hex or local Git dependency
metadata is unavailable. It warns and omits the unavailable fields.
`--offline` intentionally skips Hex enrichment. This differs from a licence
audit, where unavailable package metadata makes the report incomplete (exit `2`).

These items are required. If one fails, the command exits `2`:

- root metadata,
- valid purls for supported sources,
- valid local paths, package metadata, and dependency relationships,
- SBOM generation and file writes.

How `--reproducible` and `--offline` combine:

| Flags | Dependency metadata | If metadata is unavailable |
|---|---|---|
| `--reproducible` | Hex/Git metadata from locked source archives; local path metadata from current `gleam.toml` files. | Exit `2`. |
| `--reproducible --offline` | Hex/Git enrichment is skipped. Local path metadata and declared licences remain. | Missing or invalid local metadata exits `2`. |

## Embedded vulnerabilities

`--vulns` queries OSV.dev and adds the results to the CycloneDX
`vulnerabilities` array. Each advisory has an `id`, an `OSV` source link,
ratings, and an `affects` list. The list refers to affected components by
`bom-ref` or purl. Tools such as [Dependency-Track][dt] can read this
VEX-style document. Advisory data changes over time, so you cannot use
`--vulns` with `--offline` or `--reproducible`.

An OSV batch request failure exits `2`. An individual advisory-detail failure
warns and retains its ID with unknown severity; generation still exits `0`.
`check --checks=vulns` and `check --checks=all` exit `2` when advisory details
are unavailable: the vulnerability gate cannot evaluate their severity.

Ratings use the advisory's resolved severity, including `none` for a valid
CVSS score of `0.0`. A recognised OSV `database_specific.severity` overrides
the vectors. Raw vectors and their CVSS methods remain in the document.

## Reproducible output

By default, `sbom` uses a random `serialNumber` and the current time for
`timestamp`. The output from two runs is different. With
`--reproducible` without `--offline`, the command reads Hex metadata from each
checksum-verified package archive and Git metadata from the archive at the
locked commit. It omits mutable Hex publisher data, uses a content hash for
`serialNumber`, and gets the timestamp from [`SOURCE_DATE_EPOCH`][sde], or uses the Unix epoch if
the variable is not set. The same project files, lockfile, tool version,
options, and timestamp produce byte-identical output.
The resolved timestamp is part of the serial hash. A different timestamp
therefore produces a different `serialNumber`.

Local references remain stable when an equivalent workspace layout moves to
a different checkout directory. Changes to emitted local metadata, paths,
versions, or edges change the reproducible BOM. Local source files are not
scanned or hashed: unchanged output does **not** prove unchanged source code.
Use separate source or build attestations when that evidence is required.

Locked source archives use the same [archive limits as `notices`](/docs/notices#source-archive-limits):
64 MiB per download and 256 MiB of tar data per extraction, including Hex's
outer and inner archives. Archives at the limits are accepted. An oversized
download or invalid archive exits `2` when locked metadata is required.
The limits apply to archive sizes, not total VM memory.

The command reuses the shared [metadata cache](/docs/#caching). Entries from
locked archives do not expire. Use `--cache-dir=DIR` to select the application
cache root, or `--no-cache` to fetch the metadata again.

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
| `--cache-dir` | `STRING` |  | Use DIR as the application cache root for all cache families |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--license-text` | `BOOL` | `false` | Embed canonical SPDX text for recognised licence IDs (requires network on cache miss; conflicts with --offline) |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--offline` | `BOOL` | `false` | Skip Hex metadata fetch; with --reproducible, skip Git enrichment too. Local path metadata is always required |
| `--output` | `STRING` |  | Write SBOM to PATH instead of stdout |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--reproducible` | `BOOL` | `false` | Reproducible output from locked archives (unless --offline) and current local path metadata; serialNumber is a content hash and timestamp comes from SOURCE_DATE_EPOCH (default 1970-01-01T00:00:00Z) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
| `--vulns` | `BOOL` | `false` | Query OSV.dev and embed a CycloneDX vulnerabilities array (requires network; conflicts with --offline and --reproducible) |
<!-- cli-referencestop -->

[cyclonedx]: https://cyclonedx.org/
[dt]: https://dependencytrack.org/
[sde]: https://reproducible-builds.org/docs/source-date-epoch/
