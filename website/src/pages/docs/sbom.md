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
licence_audit sbom --reproducible      # deterministic output
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
`AND` or `OR` relationship. Therefore, `sbom` does not create an SPDX
expression.

## Supported sources

`sbom` supports only `hex` and GitHub `git` sources. It **fails** on a
dependency source that it cannot convert to a valid purl. Unsupported sources
include path dependencies and non-GitHub git dependencies. `--offline` skips
licence requests but continues to validate purls. The [`vulns`](/docs/vulns)
command has different behavior: it identifies and skips unsupported sources.

## Embedded vulnerabilities

`--vulns` queries OSV.dev and adds the results to the CycloneDX
`vulnerabilities` array. Each advisory has an `id`, an `OSV` source link,
ratings, and an `affects` list. The list refers to affected components by
`bom-ref` or purl. Tools such as [Dependency-Track][dt] can read the resultant
VEX-style document. This operation requires a network connection. Therefore,
you cannot use `--vulns` with `--offline`.

## Reproducible output

By default, `sbom` uses a random `serialNumber` and the current time for
`timestamp`. Thus, the output from two runs is different. With
`--reproducible`, the command uses a content hash for `serialNumber`. It gets
the timestamp from [`SOURCE_DATE_EPOCH`][sde], or uses the Unix epoch if the
variable is not set. You can commit and compare reproducible SBOM files to
find dependency or licence changes.

## Flags

| Flag | What it does |
|---|---|
| `--output` | Write the SBOM to `PATH` (compact) instead of stdout (pretty). |
| `--offline` | Skip the Hex metadata fetch and omit licence fields. |
| `--reproducible` | Deterministic output via a content hash and `SOURCE_DATE_EPOCH`. |
| `--vulns` | Query OSV.dev and embed a `vulnerabilities` array. Conflicts with `--offline`. |
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--cache-path` | Override the licence metadata cache location. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |

[cyclonedx]: https://cyclonedx.org/
[dt]: https://dependencytrack.org/
[sde]: https://reproducible-builds.org/docs/source-date-epoch/
