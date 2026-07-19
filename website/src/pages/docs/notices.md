---
layout: ../../layouts/DocsLayout.astro
title: notices
description: Bundle a release-ready third-party licence notices file from your locked dependencies, with automatic fallbacks when a package ships no licence text.
---

`notices` produces a plain-text third-party licence bundle for a release. It
inventories each locked dependency, includes its applicable licence text, and
preserves any package-specific `NOTICE` attribution. It's the human-readable
counterpart to [`sbom`](/docs/sbom) — similar in spirit to npm's
`generate-license-file`.

```sh
licence_audit notices                              # to stdout
licence_audit notices --output=THIRD_PARTY_LICENSES.txt
licence_audit notices --include-dev
```

By default only **production** dependencies are included; pass `--include-dev`
to add development-only dependencies.

## What the file contains

The output opens with a header naming the `manifest.toml` it was generated from,
then two kinds of sections:

- **Licence groups.** Each distinct licence text is emitted once, followed by
  the list of products that use it. Dependencies with **identical** licence text
  are grouped so a shared licence (say, the MIT text) isn't repeated per package.
- **Notice sections.** Any package-specific `NOTICE`/attribution file a
  dependency ships is preserved verbatim in its own section.

## Where licence text comes from

When a dependency's own source archive ships no licence text — for example a Hex
tarball with only a `NOTICE` file, or nothing — `notices` recovers one without
discarding what the source *did* ship. It tries these sources in order:

1. **Source archive** (highest priority). Any `LICENSE`/`LICENCE`/`COPYING`
   found in the package's own archive is used as-is, and any `NOTICE` is always
   preserved.
2. **Declared repository** (Hex packages only). The declared repository links
   are followed for `github.com`, `codeberg.org`, and `gitlab.com`. A
   deterministic tag (`v<version>`, then `<version>`) is resolved to an
   immutable commit SHA and the archive at that commit is fetched — never a
   moving branch or `HEAD`. A repository's own ancillary `NOTICE` files are
   dropped; only the licence text is taken.
3. **Canonical SPDX text**. The declared SPDX identifiers/expressions are
   expanded to canonical text from a pinned SPDX License List revision. These
   entries are clearly labelled under synthetic `SPDX-License-List/<id>.txt`
   paths. Expressions with `AND`/`OR`/`WITH`/`(…)`/trailing `+` are supported;
   for `OR`, every alternative is included.

A repository fallback that fails *transiently* is non-fatal: `notices` warns and
continues to the SPDX fallback.

## When it fails

Unlike the bare report, `notices` exits non-zero when it can't produce a
faithful bundle. It fails if:

- a selected dependency still lacks recognizable licence text after every
  fallback — including `LicenseRef-` custom licences that have no canonical text;
- a dependency's source is unsupported;
- a network, archive, checksum, SPDX, or output-write error occurs.

Hex tarballs are verified against their `outer_checksum` before use, so a
corrupted or tampered download is caught rather than silently bundled.

## Caching

Beyond the shared Hex metadata cache, `notices` keeps its own cache of the
licence materials it resolves so repeated runs don't re-download sources or
re-resolve fallbacks:

```
${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/notices-v3.dets
```

It's keyed by immutable content addresses and holds several namespaces:
extracted source materials, final per-package materials, repository tag→commit
resolutions, repository-extracted licence files, and canonical SPDX records
shared by identifier (so `Apache-2.0` is fetched at most once across every
package that declares it). Entries never expire. Override the location with
`--cache-path=PATH` or bypass it with `--no-cache`.

## Flags

| Flag | What it does |
|---|---|
| `--output` | Write the notices file to `PATH` instead of stdout. |
| `--include-dev` | Include development-only dependencies in the bundle. |
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--cache-path` | Override the licence metadata cache location. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |
