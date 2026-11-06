---
layout: ../../layouts/DocsLayout.astro
title: Quick start
description: Install licence_audit, inspect your locked dependencies, create a policy, and enforce the policy.
---

`licence_audit` is a small CLI that audits the licences used by your Gleam
project's locked dependencies. It reads `manifest.toml` and gets licence
metadata from Hex. It reports the resolved dependency tree, creates a
CycloneDX SBOM, and checks for known vulnerabilities.

## Install

Download the self-contained archive for your platform from the
[releases][releases] page. Extract the archive and put `licence_audit` on your
`PATH`. These Queso-built executables include the Erlang runtime. You do not
have to install Erlang/OTP on the target machine. Use these native binaries
for CI to avoid a separate OTP requirement.

The release also provides an escript for compatibility. **The escript needs
Erlang/OTP 28 or later for all commands.** On OTP 27, the VM can fail to load
it with `corrupt atom table` and exit `127`, before any command runs. This
unsupported-runtime failure is outside the
[CLI exit-code contract](/docs/compatibility#exit-codes-and-output-streams).

With [mise][mise], install directly from the `github:` provider:

```sh
mise use -g github:tylerbutler/licence_audit@latest
```

Replace `latest` with a tag such as `v0.7.0` to select a fixed version. mise
selects the self-contained archive for your operating system and architecture.
You do not need Erlang/OTP. For source build instructions, refer to [DEV.md][dev].

## Standard workflow

Inspect the dependencies, create a policy, and enforce the policy.

```sh
# 1. Create manifest.toml and report the dependency tree
gleam deps download
licence_audit

# 2. Select the licences to allow or deny
licence_audit update

# 3. Return a failure if the policy has a violation
licence_audit check
```

The `licence_audit` command reports policy findings without enforcing them and
returns exit code `0` when the scan completes. An incomplete licence report
caused by unavailable or invalid package metadata returns `2`. The `check`
command also returns `1` when it finds a policy violation.

## Commands

| Command | What it does |
|---|---|
| [`check`](/docs/check) | Report metadata and enforce the licence policy. Returns a nonzero exit code for violations. |
| [`notices`](/docs/notices) | Create a third-party licence notices file for a release. Does not evaluate policy. |
| [`sbom`](/docs/sbom) | Create a CycloneDX 1.6 JSON SBOM. Does not evaluate policy. |
| [`update`](/docs/update) | Select licences and write a policy to `gleam.toml`. |
| [`vulns`](/docs/vulns) | Report known vulnerabilities from OSV.dev. Does not evaluate policy. |

## Output, colours, and exit codes

Reports go to **stdout**. Progress, warnings, and errors go to **stderr**.
Rows use indentation to show the dependency tree. Each row starts with a
status symbol:

| Glyph | Meaning |
|---|---|
| `✓` | Policy permits the licence (`check` only) |
| `✗` | Policy denies the licence (`check` only) |
| `?` | No policy evaluated, or status unknown |
| `~` | Finding accepted by a scoped policy exception |
| `·` | Command skips the package (non-Hex source) |

Use `--color` or `--colour` to control colour. The permitted values are `auto`,
`always`, and `never`. The `auto` value uses `NO_COLOR`, `FORCE_COLOR`, `TERM`,
`CI`, and `COLORTERM`.

The command uses these exit codes:

| Code | Meaning |
|---|---|
| `0` | Successful completion. Report-only policy violations and vulnerabilities do not fail the command. |
| `1` | Enforced check failure, invalid usage, or non-interactive use of `update`. |
| `2` | Input, config, manifest, network, decode, or artifact-generation error that prevents completion, including incomplete licence metadata and `update` edit/write failures. |
| `130` | `update` cancelled by the user. |

Individual advisory details and default SBOM dependency enrichment are optional:
their failures warn but can still exit `0`. Required metadata and OSV batch
failures exit `2`. See the [partial-result rules](/docs/compatibility#exit-codes-and-output-streams)
for the command-specific exceptions and release impact.

## Compatibility

From version 1.0.0, the CLI and configuration follow the
[compatibility policy](/docs/compatibility). Read it for versioning rules,
stable interfaces, output guarantees, and exceptions for correctness fixes.
Gleam modules and human-readable report formatting are not supported
integration interfaces.

## Caching

`licence_audit` caches Hex licence metadata on disk between runs at
`${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/hex-v2.sqlite3`. Override it with
`--cache-path=PATH`, or bypass the caches with `--no-cache`. `licence_audit`
reuses Hex API entries for 7 days, so metadata changes on Hex can take up to
7 days to appear. Use `--no-cache` when you need fresh data.

The cache is shared across projects and commands for each package name and
version. Concurrent commands can share the cache on a local filesystem. In
CI, restore and save the cache directory between jobs, for example with
`actions/cache`, `--cache-path=.hex-cache/hex-v2.sqlite3`, and `.hex-cache/` as
the path to save. Use `--verbose` to see cache hits and misses.

SQLite WAL allows reads during writes. Busy operations are skipped without
waiting and produce a warning. Save CI caches only after all commands finish;
copying an active database can omit committed WAL data.

The cache is a SQLite file that fills on first use. `licence_audit` does not
read or change old `.dets` files. If `--cache-path` points to a `.dets` file,
choose a new path.
The current cache driver requires ASCII-only paths. If its native library is
missing or cannot load, the command warns and continues without caching.
`--no-cache` bypasses the driver without attempting to load it.

Escript archives include a `sqlite_native/` directory beside the escript.
Keep this directory with the executable for caching; no `ERL_LIBS` setting
is needed. A bare escript warns and runs without caching. `--no-cache` skips
the native-library load attempt and its warning.

On Linux, keep absolute database paths within 504 bytes, including directories.
Longer paths are unsupported. Some failed opens can abort the VM because of
an upstream driver bug tracked in [#168][cache-bug]. Use a shorter
`XDG_CACHE_HOME` or `--cache-path`, or use `--no-cache`.

`licence_audit` caches each successful lookup when it completes. A later
lookup failure keeps earlier entries, and the audit continues with the
remaining packages. The cache excludes failed lookups. If a refresh fails
and an older entry exists, the audit uses that entry and warns.

If a cache operation fails, `licence_audit` continues the audit and writes a
warning to stderr. It does not cache OSV advisories.

Hex network errors include the request URL and available DNS, connection,
or TLS details for IPv4 and IPv6. Request timeout errors include the
5000 ms limit. When the HTTP client does not identify the failed stage,
the message says so.

## Set up with an AI agent

Install the setup skill with [APM][apm]:

```sh
apm install tylerbutler/licence_audit/.apm/skills/setup-licence-audit
```

This installs the setup skill, not the executable or repository development
skills. Ask your agent:

> Set up licence_audit for local licence and vulnerability checks in this
> project. Preserve the existing policy and tool versions. Do not change CI.

To include CI, add:

> Also enforce the same licence policy and vulnerability threshold in CI.

The skill adds CI only when requested. You make the licence approval decisions.
For manual CI setup, install a fixed release and run `licence_audit check`
against a policy committed to version control.

## Troubleshooting

- **Manifest not found:** run `gleam deps download` to create `manifest.toml`.
- **Hex request fails:** retry or reuse cached entries without `--no-cache`.
  Required metadata failures still make a licence report incomplete.
- **Unsupported SBOM source:** `sbom` requires a valid purl for every dependency;
  `--offline` does not bypass source validation.
- **OSV.dev unavailable:** vulnerability commands need access to `api.osv.dev`.
  Advisory responses are not cached.
- **No colours in automated output:** use `--color=always` to force ANSI codes
  or `--color=never` for plain text. `--colour` is an alias.

Licence audits cover locked Hex packages. Non-Hex sources remain in the tree
and are identified as skipped. Hex licence metadata is package-level data,
not a source inspection or a per-release licence conclusion.

## Root usage and flags

This section is generated from the CLI. Use `licence_audit --help` for the
options available in your installed version.

<!-- cli-reference -->
Reports Hex package licence metadata. It displays a summary of the licences for the project's dependencies. Use the `check` subcommand to enforce a licence policy, and the `update` subcommand to create a policy.

**Usage:**

```
licence_audit (check | notices | sbom | update | vulns) [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--allow` | `STRING_LIST` | `` | Allow licences, comma-separated |
| `--cache-path` | `STRING` |  | Override the licence metadata cache location |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--deny` | `STRING_LIST` | `` | Deny licences, comma-separated |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--prod-only` | `BOOL` | `false` | Only audit production dependencies; ignore dev-dependency violations |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
| `--version` | `BOOL` | `false` | Print the installed version |
<!-- cli-referencestop -->

[releases]: https://github.com/tylerbutler/licence_audit/releases
[mise]: https://mise.jdx.dev/
[dev]: https://github.com/tylerbutler/licence_audit/blob/main/DEV.md
[apm]: https://github.com/microsoft/apm
[cache-bug]: https://github.com/tylerbutler/licence_audit/issues/168
