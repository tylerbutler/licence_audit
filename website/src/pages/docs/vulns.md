---
layout: ../../layouts/DocsLayout.astro
title: vulns
description: Report known vulnerabilities for your locked dependencies using the OSV.dev database. Does not evaluate licence policy.
---

`vulns` queries [OSV.dev][osv] and lists each affected package with its OSV /
GHSA / CVE identifiers, a severity bucket, and a one-line summary. It does
**not** evaluate licence policy.

```sh
licence_audit vulns
```

## What it reports

Each affected package is listed with its identifiers, a severity bucket
(`critical` \| `high` \| `medium` \| `low` \| `unknown`), and a short summary,
ending with a checked / affected / clean tally. Severity comes from OSV's
`database_specific.severity`, falling back to the CVSS vector.

`vulns` never fails on the *presence* of a vulnerability — only on I/O,
manifest, or network errors. Hex and GitHub deps are queried; other sources are
skipped and listed at the end. Advisories are fetched over HTTPS and are **not**
cached.

## Failing a build on vulnerabilities

`vulns` itself is report-only. To *fail* when advisories meet a severity
threshold, add `--vulns` to [`check`](/docs/check):

```sh
licence_audit check --vulns
licence_audit check --vulns --vuln-severity=medium
```

That runs the licence audit, then queries OSV.dev and fails when any advisory's
severity meets or exceeds the threshold. Unknown-severity advisories are shown
but never fail.

## Flags

| Flag | What it does |
|---|---|
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--color` | Colourise output: `auto` (default) \| `always` \| `never`. Alias `--colour`. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |

[osv]: https://osv.dev/
