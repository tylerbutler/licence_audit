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

For each affected package, `vulns` shows its identifiers, severity, and a short
summary. Severity is `critical`, `high`, `medium`, `low`, or `unknown`. The
command first reads `database_specific.severity` from OSV. If this value is not
available, it uses the CVSS vector. The report ends with the numbers of checked,
affected, and clean packages.

The presence of a vulnerability does not cause `vulns` to fail. I/O, manifest,
and network errors cause a failure. The command queries Hex and GitHub
dependencies. It skips other sources and lists them at the end. The command
gets advisories through HTTPS and does **not** cache them.

## Failing a build on vulnerabilities

`vulns` reports results and does not enforce a threshold. To return a failure
when advisories meet a severity threshold, add `--vulns` to
[`check`](/docs/check):

```sh
licence_audit check --vulns
licence_audit check --vulns --vuln-severity=medium
licence_audit check --vulns --vuln-block-unknown
```

The command runs the licence audit and then queries OSV.dev. It fails when an
advisory meets or exceeds the threshold. An advisory with unknown severity does
not cause a failure by default. Use `--vuln-block-unknown` to make unknown
severity cause a failure. See [`check`](/docs/check#also-fail-on-vulnerabilities)
for configuration and override rules.

## Flags

| Flag | What it does |
|---|---|
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--color` | Colourise output: `auto` (default) \| `always` \| `never`. Alias `--colour`. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |

[osv]: https://osv.dev/
