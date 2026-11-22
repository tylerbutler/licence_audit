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

## Report contents

For each affected package, `vulns` shows its identifiers, severity, and a short
summary. Severity is `critical`, `high`, `medium`, `low`, `none`, or `unknown`.
For package-specific OSV scores, the command selects the affected entry for the
queried package and locked version. It matches explicit versions and SemVer
ranges. Other range types require OSV's enumerated versions; the command does not
infer Git ancestry from commit hashes. Scores for another package or version do
not apply.

Without matching package-specific scores, the command uses the advisory's
`database_specific.severity`, then its top-level CVSS vectors. The report ends
with the numbers of checked, affected, and clean packages.

A valid CVSS score of `0.0` has severity `none`, not `low` or `unknown`.
It remains in the report but never blocks a selected vulnerability gate, even with
`--vuln-block-unknown`. When OSV supplies multiple vectors, the highest known
severity applies. A recognised `database_specific.severity` remains authoritative
for the top-level fallback.

A vulnerability does not make `vulns` fail. Exit codes:

- `0`: the scan completes, with or without findings.
- `2`: an input, configuration, manifest, or OSV batch network or decode
  error.

If the request for one advisory fails, the report keeps the advisory ID with
unknown severity and a warning. The command still exits `0`. The severity is
then incomplete. Network diagnostics include the request URL and transport
reason, such as a DNS, connection, TLS, or timeout error.

The command queries Hex and GitHub dependencies. It skips other sources and
lists them at the end. It gets advisories through HTTPS and does **not** cache
them.

Initial OSV requests contain at most 1,000 queries each. The CLI keeps input
order and follows each result's pagination, with a limit of 32 pages per query.
If a later batch or page fails, the command returns an error instead of partial
coverage. OSV requests use the shared [network retry limits](/docs/#network-retries).

Hex queries identify the package and locked version. GitHub queries send the
locked commit through OSV's `commit` field. Reports, scoped exceptions, and
SBOM component references keep the full GitHub purl, including any `#subpath`;
the commit query excludes that path. These query rules also apply
to `check --checks=vulns`, `check --checks=all`, and `sbom --vulns`.

## Reviewed advisory exceptions

`vulns` uses [configuration discovery](/docs/configuration#discovery) to read
`[tools.licence_audit]`.
It shows matching advisory exceptions with their reasons and expiry dates,
but keeps the advisories in the affected-package counts. An exception does
not mean that a vulnerability has been fixed.

Use `--config=other.toml` to select another configuration file, or
`--ignore-config` to ignore configuration. The command does not require a
licence policy. It reports licence exceptions as `not evaluated`.

The exception summary lists expired and unused entries. Expiry does not make
`vulns` enforce a gate. Malformed or overlapping exception configuration
returns exit code 2. A failed advisory detail lookup still appears as
unavailable evidence with a warning; an exception cannot accept that
placeholder.

See [scoped policy exceptions](/docs/check#scoped-policy-exceptions) for the
TOML schema, exact version/commit matching, advisory aliases, and UTC expiry.

## Failing a build on vulnerabilities

`vulns` reports results and does not enforce a threshold. To return a failure
when advisories meet a severity threshold, select `--checks=vulns` on
[`check`](/docs/check):

```sh
licence_audit check --checks=vulns
licence_audit check --checks=vulns --vuln-severity=medium
licence_audit check --checks=vulns --vuln-block-unknown
```

This selection queries OSV.dev without licence metadata requests or licence
enforcement. It works with or without a licence policy. Use `--checks=all`
to retain the combined licence and vulnerability gate:

```sh
licence_audit check --checks=all
```

The vulnerability gate fails when an
advisory meets or exceeds the threshold. An advisory with unknown severity does
not cause a failure by default. Use `--vuln-block-unknown` to make unknown
severity cause a failure. See [`check`](/docs/check#also-fail-on-vulnerabilities)
for configuration and override rules.

The gate evaluates severity and exceptions for each package/advisory occurrence.
Its advisory counts include a shared advisory once, even when affected packages
have different severities.

## Flags

`vulns` defaults to `--scope=all`, which includes development dependencies.
Use `--scope=prod` to
exclude them. OSV advisories are not cached; this command does not accept
`--no-cache` or `--cache-dir`.

Scope follows the production dependency graph in the `gleam.toml` beside the
selected manifest. A valid file without `[dependencies]`, or with an empty
table, has no production dependencies, so `--scope=prod` makes no OSV requests.
A missing file uses all lockfile direct dependencies as production roots.
An unreadable file, invalid TOML, or a `dependencies` value that is not a table
causes exit code `2`, including with `--ignore-config`.

<!-- cli-reference -->
Report known vulnerabilities for locked dependencies using the OSV.dev database. Does not evaluate licence policy. Includes dev dependencies unless --scope=prod is set. Queries OSV directly and uses no on-disk cache.

**Usage:**

```
licence_audit vulns [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--scope` | `STRING` | `all` | Dependency scope: prod\|all (production only or all dependencies) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->

[osv]: https://osv.dev/
