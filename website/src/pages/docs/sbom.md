---
layout: ../../layouts/DocsLayout.astro
title: sbom
description: Create a CycloneDX 1.6 or SPDX 2.3 JSON SBOM from your locked dependency tree. Does not evaluate licence policy.
---

`sbom` creates a [CycloneDX 1.6][cyclonedx] document by default, or an
[SPDX 2.3 JSON][spdx] document with `--format=spdx-json`. Both describe all
locked dependencies. The command does **not** evaluate licence policy.

```sh
licence_audit sbom                     # pretty JSON to stdout
licence_audit sbom --output=sbom.json  # pretty JSON to a file
licence_audit sbom --offline           # prohibit network; read files and caches
licence_audit sbom --reproducible      # reproducible output
licence_audit sbom --vulns             # embed OSV vulnerabilities
licence_audit sbom --licence-text      # embed canonical SPDX licence text
licence_audit sbom --format=spdx-json  # SPDX 2.3 instead of CycloneDX
```

## SPDX format

`--format=spdx-json` reuses the locked package graph and licence metadata.
It includes package URLs, locked Hex SHA-256 checksums, a root package, and
`DESCRIBES` and `DEPENDS_ON` relationships. It does not add file analysis,
copyright evidence, or source-level licence conclusions.

Local packages use the same metadata and publication verification as
CycloneDX. Their normalized paths appear in `comment`; `downloadLocation`
stays `NOASSERTION`. A verified publication adds a purl, but does not add a
source hash or prove that local files match the release. An unpublished
local package has no purl. Missing required evidence fails before output.

A single recognised SPDX licence ID becomes `licenseDeclared`. Missing
declarations use `NOASSERTION`. Custom names, expressions, and multiple
declarations use `NOASSERTION` and preserve the original declarations in
`licenseComments`. The tool does not infer `AND` or `OR`, or invent custom
licence text. `licenseConcluded` is always `NOASSERTION`.

SPDX output rejects `--vulns` and `--licence-text` (alias `--license-text`)
with exit code `2` before network requests or artifact writes. Both flags
remain CycloneDX-only. SPDX tag-value and SPDX 3 are not supported.

## CycloneDX document contents

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

Use `--license-text` as a supported alias for `--licence-text`. Both spellings
accept a bare flag, `=true`, or `=false`. A bare flag toggles the value; an
explicit value sets it. Repeated flags, including mixed spellings, apply in
argument order.

`--licence-text` adds canonical SPDX License List text to recognised licence
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

This flag works with `--offline` when the cache contains the required pinned
text. Missing or invalid text exits `2`; the command does not make a network
request or omit requested text. It also works with `--reproducible` because
the SPDX revision is fixed. Use `--no-cache` to bypass the caches without deleting entries.
`--cache-dir=DIR` selects the shared application root, including the
`spdx-v1/` text cache and `hex-v2/` metadata cache.

A failed text request, invalid SPDX response, or missing text for a recognised
ID exits `2` before writing the SBOM. Optional package metadata enrichment
remains unchanged: a dependency without licence metadata has no licence text.

## Supported sources

`sbom` supports `hex`, GitHub `git`, and local path sources (`source = "local"`
or the `"path"` alias). Non-GitHub git and unknown sources still fail.
`--offline` does not bypass source or local metadata validation.
The standalone [`vulns`](/docs/vulns) command skips local sources; it does not
verify their publication identities. `sbom --vulns` can query a verified local
publication identity and retains the local component reference in `affects`.

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

The reference identifies a component within the document. It does not verify
local source contents. Local components have no archive hash, registry
supplier, tarball reference, or signature. A declared repository supplies a
source link; it does not prove a Hex publication.

### Publication verification

For each local package, `sbom` checks the Hex release endpoint for its locked
name and version. A matching release response adds `pkg:hex/<name>@<version>`
as the component's purl. The component keeps its local `bom-ref`, source
properties, metadata, and graph edges. The lookup verifies publication of the
name/version, not that your files match the release archive.

Only a release-endpoint HTTP `404` confirms an unpublished package. That
component has no purl. Network, rate-limit, server, decode, and identity
mismatch errors do not prove absence. If the command has no usable cached
verification result, these failures exit `2` before writing output.

`--cache-dir=DIR` selects the application root for this evidence. The internal
`publication-v1/` family stores name/version records. Confirmed published
results have no expiry. Confirmed unpublished results remain usable for less
than 24 hours after verification; at 24 hours, an online run must revalidate.
Offline runs reject expired, missing, or invalid verification data.

`--no-cache` bypasses verification storage without deleting it. Online runs
must still verify local publication. Offline runs with local components and
`--no-cache` exit `2`, even if the disk contains earlier evidence.

### Paths and metadata

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
The root project's local declarations must match locked targets and direct
dependency names.
Root `[dev_dependencies]` local packages are included with optional scope.
For Git dependencies, `path` selects a package inside the repository; it is
not a local filesystem dependency.
Missing paths or metadata, malformed metadata fields, stale identities or
edges, duplicate locked names, and cycles involving local components exit `2`
before output is written. Run `gleam deps download` to refresh a stale lockfile.

The root lockfile supplies the complete graph. No member manifest is required,
and workspace members' own development dependencies are not added.
Every root and package dependency must have a locked target, including in
Hex-only graphs. A missing target or a malformed Hex SHA-256 checksum exits
`2` before output is written.
Local description, licence, link, and repository metadata is read on every
run, including `--reproducible --offline`; it is not cached.

## Completion and optional enrichment

Default `sbom` generation exits `0` when optional Hex or local Git dependency
metadata is unavailable. It warns and omits the unavailable fields.
`--offline` reads cached Hex enrichment and local Git files, but does not
fetch missing optional metadata. This differs from a licence audit, where
unavailable required package metadata makes the report incomplete (exit `2`).

These items are required. If one fails, the command exits `2`:

- root metadata,
- valid Hex SHA-256 checksums and a complete locked dependency graph,
- valid purls for supported sources,
- valid local paths, package metadata, and dependency relationships,
- usable publication verification for local packages,
- locked Hex/Git metadata when `--reproducible` is selected,
- pinned SPDX text when `--licence-text` is selected,
- SBOM generation and file writes.

How `--reproducible` and `--offline` combine:

| Flags | Dependency metadata | If metadata is unavailable |
|---|---|---|
| `--reproducible` | Hex/Git metadata from locked source archives or immutable cache entries; current local `gleam.toml` files and publication evidence. | Exit `2`. |
| `--reproducible --offline` | The same required metadata, using local files and usable cached evidence without network access. | Missing required metadata or verification exits `2`. |

To prepare an offline reproducible run, first run `sbom --reproducible` online
with the same `--cache-dir`. Include `--licence-text` in that run if you need
offline licence text. Preserve the cache root between runs or CI jobs.
`--offline` does not relax evidence requirements selected by other flags.

## Embedded vulnerabilities

`--vulns` queries OSV.dev and adds the results to the CycloneDX
`vulnerabilities` array. Each advisory has an `id`, an `OSV` source link,
ratings, and an `affects` list. The list refers to affected components by
`bom-ref`, including local references for verified published local packages.
These advisories describe the published identity; they do not scan or verify
local source changes. Tools such as [Dependency-Track][dt] can read this
VEX-style document. Advisory data changes over time, so you cannot use
`--vulns` with `--offline` or `--reproducible`.

An OSV batch request failure exits `2`. An individual advisory-detail failure
warns and retains its ID with unknown severity; generation still exits `0`.
`check --checks=vulns` and `check --checks=all` exit `2` when advisory details
are unavailable: the vulnerability gate cannot evaluate their severity.

Ratings use the [severity for each queried package and version](/docs/vulns#report-contents),
including `none` for a valid CVSS score of `0.0`. Each advisory appears once,
with the distinct ratings for its selected components. Ratings for other
packages or versions do not enter the document. Without matching package-specific
scores, a recognised OSV `database_specific.severity` overrides the advisory's
top-level vectors. Raw vectors and their CVSS methods remain in the document.

## Reproducible output

By default, `sbom` uses a random `serialNumber` and the current time for
`timestamp`. The output from two runs is different. With
`--reproducible`, the command reads Hex metadata from each
checksum-verified package archive and Git metadata from the archive at the
locked commit. It omits mutable Hex publisher data, uses a content hash for
`serialNumber`, and gets the timestamp from
[`SOURCE_DATE_EPOCH`](/docs/environment). See that table for parsing and
fallback rules under the [reproducible-builds convention][sde].
The same project files, lockfile, publication evidence,
tool version, options, and timestamp produce byte-identical output, including
online and offline runs with matching usable cache inputs.
SPDX uses `documentNamespace` and `creationInfo.created` instead of
`serialNumber` and `timestamp`, with the same reproducibility guarantees.
The resolved timestamp is part of the serial hash. A different timestamp
therefore produces a different `serialNumber`.

Local references remain stable when an equivalent workspace layout moves to
a different checkout directory. Changes to emitted local metadata, paths,
versions, or edges change the reproducible BOM. Local source files are not
scanned or hashed: unchanged output does **not** prove unchanged source code.
Use separate source or build attestations when that evidence is required.

The manifest alone does not fix local SBOM output over time. After an
unpublished verification expires, a refreshed lookup can confirm a new
publication and add a purl. This changes the output and content-derived serial
without changing the local reference. No verification snapshot is required
or created.

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
Generate a CycloneDX 1.6 or SPDX 2.3 JSON SBOM from manifest.toml. Does not evaluate licence policy. Includes all dependencies; CycloneDX records their scope. JSON output stays plain in every color mode.

**Usage:**

```
licence_audit sbom [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-dir=<DIR>` | `DIR` |  | Use DIR as the application cache root for all cache families |
| `--color=<auto\|always\|never>` | `auto\|always\|never` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--format=<cyclonedx-json\|spdx-json>` | `cyclonedx-json\|spdx-json` | `cyclonedx-json` | Output format: cyclonedx-json or spdx-json |
| `--licence-text` | `BOOL` | `false` | Embed canonical SPDX text (alias: --license-text); CycloneDX only, offline requires usable pinned text in the cache |
| `--manifest=<PATH>` | `PATH` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--offline` | `BOOL` | `false` | Prohibit network access; use local files and usable cached evidence. Required metadata, publication verification, and requested SPDX text must remain available |
| `--output=<PATH>` | `PATH` |  | Write SBOM to PATH instead of stdout (alias: -o) |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--reproducible` | `BOOL` | `false` | Reproducible output from locked metadata, current local metadata, and publication evidence; serialNumber is a content hash and timestamp comes from SOURCE_DATE_EPOCH (default 1970-01-01T00:00:00Z) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
| `--vulns` | `BOOL` | `false` | Query OSV.dev and embed a CycloneDX vulnerabilities array (requires network; conflicts with --offline and --reproducible) |
<!-- cli-referencestop -->

[cyclonedx]: https://cyclonedx.org/
[spdx]: https://spdx.github.io/spdx-spec/v2.3/
[dt]: https://dependencytrack.org/
[sde]: https://reproducible-builds.org/docs/source-date-epoch/
