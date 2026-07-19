---
layout: ../../layouts/DocsLayout.astro
title: check
description: Report Hex package licence metadata and enforce your configured licence policy, exiting non-zero on violations.
---

`check` runs the same audit as the bare command, then **enforces** your policy.
It exits non-zero on any violation, which makes it the command you reach for in
CI.

```sh
licence_audit check
```

## Define a policy

Policy lives under `[tools.licence_audit]` in `gleam.toml`:

```toml
[tools.licence_audit]
allow = ["Apache-2.0", "MIT"]
deny  = ["GPL-3.0-only"]
```

An `allow` list means *only* those licences are accepted; a `deny` list rejects
matching licences. The easiest way to create this is [`licence_audit
update`](/docs/update), which fetches metadata, preselects existing entries,
prompts you, and writes the result back with comments preserved.

## Ad-hoc and merged policy

CLI `--allow` / `--deny` values merge with config, so you can tighten a policy
for a single run:

```sh
licence_audit check --allow=Apache-2.0,MIT --deny=GPL-3.0-only
```

Point `--config=other.toml` at a different file (it must still have a
`[tools.licence_audit]` section), or pass `--ignore-config` to use only CLI
flags.

> **Tip** — `--allow` / `--deny` also work on the bare command. There they
> switch the report into a policy *preview* but still exit `0`. Use `check` when
> you want failures.

## Production-only gates

Use `--prod-only` when your gate should consider only production dependencies.
Dev-dependency licence violations are then ignored — useful for CI checks that
shouldn't fail on tooling-only packages.

## Also fail on vulnerabilities

Add `--vulns` to run the licence audit and then query OSV.dev, failing when any
advisory's severity meets or exceeds a threshold:

```sh
licence_audit check --vulns
licence_audit check --vulns --vuln-severity=medium
```

The threshold is `low` \| `medium` \| `high` (default) \| `critical`.
Unknown-severity advisories are reported but never fail. `check --vulns` also
fails if OSV.dev can't be reached, since the check couldn't complete. The
threshold can live in config too (CLI flags win):

```toml
[tools.licence_audit]
vuln_severity = "high"
```

## Flags

| Flag | What it does |
|---|---|
| `--allow` | Allow licences, comma-separated. Merges with config. |
| `--deny` | Deny licences, comma-separated. Merges with config. |
| `--prod-only` | Only audit production dependencies. |
| `--vulns` | Also query OSV.dev and fail on advisories at or above `--vuln-severity`. |
| `--vuln-severity` | Minimum failing severity: `low` \| `medium` \| `high` (default) \| `critical`. |
| `--config` | Read configuration from `PATH`. |
| `--ignore-config` | Ignore configuration files; use only CLI flags. |
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--cache-path` | Override the licence metadata cache location. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--color` | Colourise output: `auto` (default) \| `always` \| `never`. Alias `--colour`. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |
