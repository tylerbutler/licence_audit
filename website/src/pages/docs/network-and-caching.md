---
layout: ../../layouts/DocsLayout.astro
title: Network and caching
description: Retry limits for Hex and OSV.dev requests, and the shared cache that lets later scans skip downloads.
---

Each scan needs package data from Hex and, for vulnerability checks, from
OSV.dev. This page explains how the CLI handles failed requests, and how it
keeps results so that later scans do not repeat the downloads.

## Network retries

For Hex API and publication requests, the CLI permits one retry. For OSV batch
and advisory requests, it permits two retries. These limits apply to rate limits,
transient server errors, timeouts, and known connection failures. TLS verification,
invalid input, and decode errors do not cause retries. Archive downloads keep
their existing transport behavior.

Each logical request has a total retry-wait budget of 30 seconds, separate from
its per-attempt network timeout. The CLI honors usable `Retry-After` values
(seconds or HTTP dates) and `x-ratelimit-reset` deadlines. If a deadline requires
more than the remaining budget, the request fails without an early retry.
Without a usable deadline, retries wait one second, then two seconds.

After three consecutive logical requests exhaust their attempts with timeout
or connection failures, the CLI stops new requests to that service host for
the rest of the command. Successful responses reset the failure count; rate
limits do not increase it. Hex package and publication requests share a count,
as do OSV batch and advisory requests. A new command resets the counts.

Required network failures leave coverage incomplete and return exit code `2`.
Optional SBOM enrichment and individual advisory-detail failures keep their
existing warnings and fallback behavior.

## Caching

`licence_audit` stores cache families below one application root.
See [environment variables](/docs/environment#cache-selection) for default
paths, Windows fallback, and precedence. Use `--cache-dir=DIR`
to select a root for metadata, locked-source metadata, notice materials, and
SPDX text. An explicit root takes precedence over environment discovery.
Use `--no-cache` to bypass reads and writes without deleting entries.
Do not combine enabled `--no-cache` with `--cache-dir`; this is a usage error
(exit `2`). See the [usage migration notes](/docs/compatibility#pre-10-usage-migration).
Licence reports, `check`, and `update` share the immutable metadata cache with
`sbom --reproducible`. Each key includes the package name, locked version, and
archive checksum. These entries do not expire. The first scan downloads each
locked tarball, which is larger than an API response; later scans reuse its
verified metadata.

Optional API enrichment for default SBOMs and notices uses separate
`name@version` entries with a 7-day lifetime. API licences do not determine
licence report, check, or update results. `--no-cache` bypasses both entry types
and still requires checksum verification for licence scans.

The cache is shared across projects and commands. Concurrent commands can
share the cache. In CI, restore and save the
cache directory between jobs, for example with `actions/cache`,
`--cache-dir=.hex-cache`, and `.hex-cache/` as the path to save. Use
`--verbose` to see cache hits and misses.

The root contains versioned family directories:

- `hex-v2/`: Hex API metadata and checksum/commit-keyed locked-source metadata.
- `notices-v3/`: package and source materials, including repository resolutions.
- `spdx-v1/`: pinned SPDX indexes and canonical licence/exception text.
- `publication-v1/`: verified Hex publication identities for local SBOM components.

The versioned directories are internal storage details, not CLI options.
Confirmed local publications do not expire. Confirmed unpublished results
expire at 24 hours; offline runs require usable verification evidence.
See the [local SBOM contract](/docs/sbom#publication-verification).

Each family contains one JSON file for each entry. A command writes
each entry to a temporary file and then renames it, so other commands never
read a partial entry. You can copy the cache directory at any time. To clear
the cache, delete the directory.

The cache fills on first use. `licence_audit` does not read or change old
`.dets` or `.sqlite3` cache files. You can delete them. If `--cache-dir`
points to a file, the command warns and continues without caching.

**Migration:** replace `--cache-path=.hex-cache/hex-v2` with
`--cache-dir=.hex-cache`. The old flag is rejected. Compatible metadata and
immutable materials remain usable in their existing versioned directories.
Pinned SPDX entries in `notices-v3/` are copied into `spdx-v1/` on a hit.
Other incompatible layouts are cache misses; no repair or deletion is required.

`licence_audit` caches each successful lookup when it completes. A later
lookup failure keeps earlier entries, and the audit continues with the
remaining packages. The cache excludes failed lookups. Failed archive
downloads, checksum verification, or metadata decoding cannot fall back to API
licences. Optional API enrichment can use an older API entry if a refresh fails.

If a cache operation fails, `licence_audit` continues the audit and writes a
warning to stderr. It does not cache OSV advisories.

Hex API network errors include the request URL and available DNS, connection,
or TLS details for IPv4 and IPv6. API request timeout errors include the
5000 ms limit. Archive downloads have a 30-second timeout.
