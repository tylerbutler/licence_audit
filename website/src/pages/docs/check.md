---
layout: ../../layouts/DocsLayout.astro
title: check
description: Report Hex package licence metadata and enforce your licence policy. Return a nonzero exit code for violations.
---

`check` runs the same audit as the command with no subcommand. It then
**enforces** your policy. It returns a nonzero exit code when it finds a
violation. Use `check` in CI.

```sh
licence_audit check
```

## Define a policy

Add the policy to `[tools.licence_audit]` in `gleam.toml`:

```toml
[tools.licence_audit]
allow = ["Apache-2.0", "MIT"]
deny  = ["GPL-3.0-only"]
```

An `allow` list permits only the specified licences. A `deny` list rejects
matching licences. To create the policy, use [`licence_audit
update`](/docs/update). The command gets metadata, selects existing entries,
asks you to confirm the selection, and writes the result. It preserves
comments in `gleam.toml`.

## Ad-hoc and merged policy

The command merges CLI `--allow` and `--deny` values with the configuration.
Use these options to add restrictions for one run:

```sh
licence_audit check --allow=Apache-2.0,MIT --deny=GPL-3.0-only
```

Use `--config=other.toml` to read a different file. The file must have a
`[tools.licence_audit]` section. Use `--ignore-config` to use only CLI options.

> **Note:** `--allow` and `--deny` also work on the bare command. These options
> show a policy preview, but the command returns exit code 0. Use `check` to
> return a failure for a violation.

## Production-only gates

Use `--prod-only` when your gate should consider only production dependencies.
The command then ignores licence violations in development dependencies. This
option prevents tooling-only packages from causing a CI failure.

## Also fail on vulnerabilities

Add `--vulns` to run the licence audit and query OSV.dev. The command fails
when an advisory meets or exceeds the severity threshold:

```sh
licence_audit check --vulns
licence_audit check --vulns --vuln-severity=medium
licence_audit check --vulns --vuln-block-unknown
```

The threshold is `low` \| `medium` \| `high` (default) \| `critical`.
The command reports advisories with unknown severity, but these advisories do
not cause a failure by default. Use `--vuln-block-unknown` to make these
advisories cause a failure. `check --vulns` fails if it cannot connect to OSV.dev
because it cannot complete the check. You can set the threshold in the
configuration:

```toml
[tools.licence_audit]
vuln_severity = "high"
vuln_block_unknown = true
```

`--vuln-severity` overrides the configured threshold. `--vuln-block-unknown`
can only enable blocking: if you omit it, a configured `true` still applies.
There is no CLI flag to turn this setting off. Use `--ignore-config` to ignore
both configured vulnerability settings and use CLI-only defaults, which do
not block unknown severity.

## Flags

| Flag | What it does |
|---|---|
| `--allow` | Allow licences, comma-separated. Merges with config. |
| `--deny` | Deny licences, comma-separated. Merges with config. |
| `--prod-only` | Only audit production dependencies. |
| `--vulns` | Also query OSV.dev and fail on advisories at or above `--vuln-severity`. |
| `--vuln-severity` | Minimum failing severity: `low` \| `medium` \| `high` (default) \| `critical`. |
| `--vuln-block-unknown` | Fail `check --vulns` on advisories with unknown severity. |
| `--config` | Read configuration from `PATH`. |
| `--ignore-config` | Ignore configuration files; use only CLI flags. |
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--cache-path` | Override the licence metadata cache location. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--color` | Colourise output: `auto` (default) \| `always` \| `never`. Alias `--colour`. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |
