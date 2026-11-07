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
`--include-dev` to add development dependencies. A valid project without a
`[dependencies]` table has no production dependencies.

A missing `gleam.toml` uses all lockfile direct dependencies as production
roots. An unreadable file, invalid TOML, or a `dependencies` value that is not a
table causes exit code `2`, including with `--ignore-config` or `--include-dev`.

## Dependency filters

Set filters in the file selected by
[configuration discovery](/docs/configuration#discovery):

```toml
[tools.licence_audit.notices]
include = ["package_a", "package_b"]
exclude = ["package_b"]
```

Only `include` and `exclude` are supported in this table. An unknown key or
a malformed setting causes exit code `2`; the error names an unknown key.
The command also validates any licence policy in `[tools.licence_audit]`,
including the SPDX syntax of its `allow` and `deny` entries.

An absent or empty `include` selects all eligible locked dependencies. A
nonempty `include` selects only the named packages. `exclude` takes precedence,
so this example selects only `package_a`.

Use exact locked package names, including transitive dependencies. Unknown
names in either list cause an error, even if a scope rule or another filter
would remove them. Known development-only dependencies remain valid names,
but `include` does not make them eligible without `--include-dev`.

Filters apply to Hex, git, and path dependencies after production/development
scope selection. The command does no metadata, source, or package cache work
for filtered dependencies. If no packages remain, it writes a header-only
file without opening either cache. Filters do not change other commands.

**Compliance risk:** Excluding a dependency does not remove its licence or
attribution obligations. If you distribute it, an exclusion or incomplete
allowlist can cause a licence violation. Review the licences and the contents
of your release before you use these filters.

## File contents

The output starts with a header that identifies the source `manifest.toml`
file. Two types of sections follow:

- **Licence groups.** `notices` writes each distinct licence text one time.
  Then, it lists the packages that use the text. It groups dependencies that
  have identical licence text. Thus, the file does not repeat shared text for
  each package.
- **Notice sections.** `notices` copies each package-specific `NOTICE` or
  attribution file without changes into a separate section.

## Licence text sources

`notices` looks for licence text in the sources below, in this order. It uses
a later source only when the earlier sources give no licence text.

1. **Source archive** (highest priority). The command uses each
   `LICENSE`, `LICENCE`, or `COPYING` file in the package archive without
   changes. It also preserves each `NOTICE` file.
   Empty or whitespace-only files do not count as licence text and do not
   stop fallback to another source.
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

The SPDX fallback uses the same expression syntax as `check`. Operators must
be uppercase; spaces, tabs, and line breaks can separate tokens. Licence
identifiers are case-insensitive. Invalid expressions and custom
`LicenseRef-` or `DocumentRef-` references cannot supply canonical text.
They do not prevent use of licence text found in the source or repository.

If a temporary error occurs during a repository fallback, `notices` writes a
warning and continues to the SPDX fallback.

For local path dependencies, Gleam writes `source = "local"` in the manifest.
`notices` reads licence files and declared licences from the local package.
Relative paths resolve from the directory that contains the selected manifest.
The older `source = "path"` spelling is also accepted.

For Git dependencies with a manifest `path`, the command searches only inside
the selected package subdirectory at the locked commit. Package-root notice
files take precedence over nested files. Licence files from the repository root
or sibling packages are not included. If the selected package has no licence
text, the command uses the existing SPDX fallback. The output preserves the
manifest path, and source and final cache keys include it.

An empty Git path or `.` selects the repository root. Absolute paths and paths
with `..` components are rejected.

## Failure conditions

`notices` exits `2` if it cannot create a complete bundle. It fails in these
conditions:

- A selected dependency has no recognized licence text after all fallbacks.
  This condition includes custom `LicenseRef-` licences that have no canonical
  text.
- `notices` does not support the source of a dependency.
- A network, archive, checksum, SPDX, or output write error occurs.

Before use, `notices` compares each Hex tarball with its `outer_checksum`. The
command stops if the download is corrupt or has changed.

### Source archive limits

The command accepts at most **64 MiB (67,108,864 bytes)** per archive download
and **256 MiB (268,435,456 bytes)** of tar data per extraction. It accepts an
archive at either limit and rejects one byte over. These fixed limits apply to
Git archives, repository fallback archives, and Hex archives, including the
inner `contents.tar.gz`. An unrelated member counts towards the tar limit even
when the command reads only licence files.

The command checks `Content-Length` before collecting the body and counts
received bytes when it streams the download. It stops gzip inflation at the
tar limit. A source fetch has a total 30-second deadline, including connection
setup and an IPv6 probe. The command does not follow archive redirects.

A download-size error reports the byte limit. An oversized, corrupt, or
truncated gzip archive produces an `invalid archive` error. A package source
failure stops notice generation; a repository fallback failure warns and
continues to SPDX text. These limits bound archive sizes, not total VM memory.

## Caching

In addition to the shared Hex metadata cache, `notices` keeps a cache of
resolved licence materials. The cache prevents repeated downloads and fallback
operations:

```
${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/notices-v3/
```

Immutable content addresses are the cache keys. The cache contains extracted
source materials, final package materials, repository tag-to-commit results,
licence files from repositories, and canonical SPDX records. Packages that
declare the same identifier share one SPDX record. Cache entries do not expire.
Use `XDG_CACHE_HOME` to relocate the caches, or use `--no-cache` to bypass
both the metadata and licence materials caches. `--cache-path=DIR` overrides
only the metadata cache directory. The command reads local path dependencies
live and does not cache them.

Corrupt cached values are treated as misses. Transient network failures are
never cached as successful results.

## Flags

<!-- cli-reference -->
Generate a release-ready `THIRD_PARTY_NOTICES`-style file from locked dependencies. The output inventories each product, includes its applicable licence text, and preserves package-specific NOTICE attribution. Products with identical licence text are grouped so the shared text is emitted once. Each package's own source archive is used first; when it ships no licence text the command falls back to the declared repository (GitHub, Codeberg, or GitLab, at an immutable tag commit) and then to canonical SPDX License List text. A transient repository failure is non-fatal: it warns and continues to the SPDX fallback. Output stays plain in every color mode. Configuration reads only notices include/exclude settings; a missing notices section means no filters.

**Usage:**

```
licence_audit notices [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-path` | `STRING` |  | Override the licence metadata cache directory |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--include-dev` | `BOOL` | `false` | Include dev-only dependencies in the notice file |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--output` | `STRING` |  | Write notices to PATH instead of stdout |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->
