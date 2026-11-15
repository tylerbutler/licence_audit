---
layout: ../../layouts/DocsLayout.astro
title: Licence reports
description: Inspect locked licences and preview policy findings without enforcing them.
---

Run a licence report for your Gleam project's locked dependencies:

```sh
licence_audit report
licence_audit report --manifest=apps/server/manifest.toml
```

Text is the default and current report format. The report shows the dependency
tree, licence declarations, policy findings, scoped exceptions, and skipped
non-Hex sources. A completed report returns `0`, including when it finds policy
violations. Use [`check`](/docs/check) to enforce a policy.

You can report licences without a policy. If you select a configuration file,
it must contain a valid `[tools.licence_audit]` section. Use `--ignore-config`
for a read-only report that ignores policy files. See
[configuration discovery](/docs/configuration#discovery).

Use `--no-cache` to bypass the on-disk caches. Use `--quiet` (`-q`) or
`--verbose` (`-v`) to control progress on stderr, and `--color` (`--colour`)
to select `auto`, `always`, or `never`. Reports use stdout; input and
configuration diagnostics use stderr. Missing or invalid manifest/config
files and incomplete required metadata return `2`.

## Migrate an unnamed scan

Put `report` before the flags in an old root scan:

```sh
# Before
licence_audit --manifest=apps/server/manifest.toml --no-cache
# Now
licence_audit report --manifest=apps/server/manifest.toml --no-cache
```

A bare `licence_audit` now shows help with exit `0`, including outside a
project. It does not read project files, open caches, or make network calls.
Root scan flags produce a usage error that directs you to `report`.
Root `--help`, `-h`, and `--version` remain available; there is no `audit` alias.

## CLI reference

<!-- cli-reference -->
Report Hex package licences without enforcing policy findings. Operational failures exit 2. Use `check` to enforce a licence policy.

**Usage:**

```
licence_audit report [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--allow` | `STRING_LIST` | `` | Allow licences, comma-separated |
| `--cache-path` | `STRING` |  | Override the licence metadata cache directory |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--deny` | `STRING_LIST` | `` | Deny licences, comma-separated |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--prod-only` | `BOOL` | `false` | Only scan production dependencies; exclude dev dependencies |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->
