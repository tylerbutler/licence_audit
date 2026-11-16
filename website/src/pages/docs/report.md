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

Reports read `allow` and `deny` from the selected TOML file.
Use `--config=policies/release.toml` to select a complete alternate policy.
The default and named reports reject `--allow` and `--deny`.

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

### Intentional default report

**Accepted decision (2026-11-16):** keep the licence report as the default
action. Run `licence_audit` for a report or use `licence_audit report` when you
want an explicit command name. Keep root scan flags available in both forms.

The default action gives users direct access to the tool's licence report.
The named form supports explicit scripts and workflows without requiring a
different entry point for existing users. Use `check` when findings must fail
a gate; report findings remain non-enforcing.

Outside a project, bare invocation can fail because required project inputs
are missing. This is expected scan behavior. Use `--help` or `-h` to discover
commands without project files.

This decision supersedes the help-only root proposal in
[#277](https://github.com/tylerbutler/licence_audit/issues/277).
For reviews and future PRs, treat default scanning and its missing-project
errors as intentional UX, not defects. Changing the root to help-only
behavior requires a new maintainer decision.

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
| `--cache-dir` | `STRING` |  | Use DIR as the application cache root for all cache families |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--scope` | `STRING` | `all` | Dependency scope: prod\|all (production only or all dependencies) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->
