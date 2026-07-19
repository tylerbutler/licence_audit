---
layout: ../../layouts/DocsLayout.astro
title: sbom
description: Generate a CycloneDX 1.6 JSON SBOM from your locked dependency tree. Does not evaluate licence policy.
---

`sbom` emits a [CycloneDX 1.6][cyclonedx] document describing every locked
dependency. It does **not** evaluate licence policy.

```sh
licence_audit sbom                     # pretty JSON to stdout
licence_audit sbom --output=sbom.json  # compact JSON to a file
licence_audit sbom --offline           # skip Hex fetch, omit licence fields
licence_audit sbom --reproducible      # deterministic output
licence_audit sbom --vulns             # embed OSV vulnerabilities
```

## What's in the document

Every locked dependency becomes a component with a package URL (`pkg:hex/…` for
Hex, `pkg:github/owner/repo@<commit>` for GitHub git deps), a SHA-256 hash for
Hex packages, the package description, declared licences, and external
references (tarball, source, homepage, docs). The root component is enriched
from `gleam.toml`, and a `dependencies` graph mirrors the tree.

Licences are tagged `acknowledgement: "declared"` — they come from package
metadata, not source scanning. A package declaring **multiple** licences emits
one entry each; Hex doesn't say whether the relationship is AND or OR, so no
SPDX expression is synthesised.

## Supported sources

`sbom` **fails** on any dependency whose source can't become a clean purl (path
deps, non-GitHub git deps); only `hex` and GitHub `git` are supported.
`--offline` skips licence fetches but still validates purls. (Contrast with
[`vulns`](/docs/vulns), which silently skips unsupported sources.)

## Embedded vulnerabilities

`--vulns` queries OSV.dev and embeds the results into the document's CycloneDX
`vulnerabilities` array — one entry per advisory, each with its `id`, an `OSV`
source link, ratings, and an `affects` list referencing the affected components
by `bom-ref` / purl. The result is a single VEX-style document that tools like
[Dependency-Track][dt] can ingest directly. Because it needs the network,
`--vulns` cannot be combined with `--offline`.

## Reproducible output

By default the `serialNumber` is random and the `timestamp` is wall-clock, so
two runs never byte-match. `--reproducible` makes the `serialNumber` a content
hash and takes the timestamp from [`SOURCE_DATE_EPOCH`][sde] (falling back to
the Unix epoch) — so you can commit the SBOM and diff it over time to catch
dependency or licence drift.

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
