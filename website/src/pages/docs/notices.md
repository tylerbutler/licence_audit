---
layout: ../../layouts/DocsLayout.astro
title: notices
description: Create a third-party licence notices file from your locked dependencies. Use fallback sources when a package contains no licence text.
---

`notices` creates a plain-text third-party licence bundle for a release. It
lists each locked dependency and includes its applicable licence text. It also
preserves package-specific `NOTICE` attribution. Use [`sbom`](/docs/sbom) to
create the related machine-readable data.

```sh
licence_audit notices                              # to stdout
licence_audit notices --output=THIRD_PARTY_LICENSES.txt
licence_audit notices --include-dev
```

By default, `notices` includes only **production** dependencies. Use
`--include-dev` to add development dependencies.

## What the file contains

The output starts with a header that identifies the source `manifest.toml`
file. Two types of sections follow:

- **Licence groups.** `notices` writes each distinct licence text one time.
  Then, it lists the products that use the text. It groups dependencies that
  have identical licence text. Thus, the file does not repeat shared text for
  each package.
- **Notice sections.** `notices` copies each package-specific `NOTICE` or
  attribution file without changes into a separate section.

## Where licence text comes from

If a dependency source archive contains no licence text, `notices` uses
fallback sources. It preserves applicable files from the source archive. The
command uses these sources in sequence:

1. **Source archive** (highest priority). The command uses each
   `LICENSE`, `LICENCE`, or `COPYING` file in the package archive without
   changes. It also preserves each `NOTICE` file.
2. **Declared repository** (Hex packages only). The command follows declared
   repository links for `github.com`, `codeberg.org`, and `gitlab.com`. It
   resolves a version tag, first `v<version>` and then `<version>`, to an
   immutable commit SHA. It gets the archive for that commit, not a branch or
   `HEAD`. The command uses only the licence text from this repository. It does
   not include ancillary `NOTICE` files from the repository.
3. **Canonical SPDX text.** The command converts declared SPDX identifiers and
   expressions to canonical text from a fixed SPDX License List revision. It
   labels these entries with synthetic `SPDX-License-List/<id>.txt` paths. It
   supports expressions with `AND`, `OR`, `WITH`, parentheses, or a final `+`.
   For `OR`, the command includes each alternative.

If a temporary error occurs during a repository fallback, `notices` writes a
warning and continues to the SPDX fallback.

## When it fails

`notices` returns a nonzero exit code if it cannot create a complete bundle. It
fails in these conditions:

- A selected dependency has no recognized licence text after all fallbacks.
  This condition includes custom `LicenseRef-` licences that have no canonical
  text.
- `notices` does not support the source of a dependency.
- A network, archive, checksum, SPDX, or output write error occurs.

Before use, `notices` compares each Hex tarball with its `outer_checksum`. The
command stops if the download is corrupt or has changed.

## Caching

In addition to the shared Hex metadata cache, `notices` keeps a cache of
resolved licence materials. The cache prevents repeated downloads and fallback
operations:

```
${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/notices-v3.dets
```

Immutable content addresses are the cache keys. The cache contains extracted
source materials, final package materials, repository tag-to-commit results,
licence files from repositories, and canonical SPDX records. Packages that
declare the same identifier share one SPDX record. Cache entries do not expire.
Use `--cache-path=PATH` to change the location, or use `--no-cache` to bypass
the cache.

## Flags

| Flag | What it does |
|---|---|
| `--output` | Write the notices file to `PATH` instead of stdout. |
| `--include-dev` | Include development-only dependencies in the bundle. |
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--cache-path` | Override the licence metadata cache location. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |
