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
summary. Severity is `critical`, `high`, `medium`, `low`, or `unknown`. The
command first reads `database_specific.severity` from OSV. If this value is not
available, it uses the CVSS vector. The report ends with the numbers of checked,
affected, and clean packages.

A vulnerability does not make `vulns` fail. Exit codes:

- `0`: the scan completes, with or without findings.
- `2`: an input, configuration, manifest, or OSV batch network or decode
  error.

If the request for one advisory fails, the report keeps the advisory ID with
unknown severity and a warning. The command still exits `0`. The severity is
then incomplete.

The command queries Hex and GitHub dependencies. It skips other sources and
lists them at the end. It gets advisories through HTTPS and does **not** cache
them.

Hex queries identify the package and locked version. GitHub queries send the
locked commit through OSV's `commit` field. Reports, scoped exceptions, and
SBOM component references keep the GitHub purl. These query rules also apply
to `check --vulns` and `sbom --vulns`.

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

`--no-cache` bypasses on-disk caches. OSV advisories are not cached, so this
option does not change advisory freshness.

<!-- cli-reference -->
Report known vulnerabilities for locked dependencies using the OSV.dev database. Does not evaluate licence policy.

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
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->

[osv]: https://osv.dev/
