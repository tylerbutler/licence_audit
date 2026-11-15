---
layout: ../../layouts/DocsLayout.astro
title: Licence reports
description: Inspect locked licences and preview policy findings without enforcing them.
---

Run a licence report for your Gleam project's locked dependencies:

```sh
licence_audit
licence_audit report
licence_audit report --manifest=apps/server/manifest.toml
```

Text is the default and current report format. The report shows the dependency
tree, licence declarations, policy findings, scoped exceptions, and skipped
non-Hex sources. A completed report returns `0`, including when it finds policy
violations. Use [`check`](/docs/check) to enforce a policy.

Both the default and named report read declarations from the locked Hex
archives and verify their SHA-256 checksums against `manifest.toml`.
Checksum-keyed metadata caches avoid repeated archive downloads.

Both report forms default to `--scope=all`. Use `--scope=prod` to exclude
development-only dependencies while keeping dependencies reachable from
production roots, including shared transitive packages. See
[production scope rules](/docs/check#production-only-gates).

You can report licences without a policy. If you select a configuration file,
it must contain a valid `[tools.licence_audit]` section. Use `--ignore-config`
for a read-only report that ignores policy files. See
[configuration discovery](/docs/configuration#discovery).

Use `--no-cache` to bypass the on-disk caches. Use `--quiet` (`-q`) or
`--verbose` (`-v`) to control progress on stderr, and `--color` (`--colour`)
to select `auto`, `always`, or `never`. Reports use stdout; input and
configuration diagnostics use stderr. Missing or invalid manifest/config
files and incomplete required metadata return `2`.

## Default and named reports

The named command is optional. These commands use the same options and
produce the same non-enforcing report:

```sh
licence_audit --manifest=apps/server/manifest.toml --no-cache
licence_audit report --manifest=apps/server/manifest.toml --no-cache
```

A bare `licence_audit` runs the default report. Outside a project, missing
project inputs cause an operational error, as with the named command.
Use root `--help`, `-h`, or `--version` without reading project files,
opening caches, or making network calls. There is no `audit` alias.

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
| `--cache-dir` | `STRING` |  | Use DIR as the application cache root for all cache families |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--deny` | `STRING_LIST` | `` | Deny licences, comma-separated |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--scope` | `STRING` | `all` | Dependency scope: prod\|all (production only or all dependencies) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->
