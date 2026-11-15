---
layout: ../../layouts/DocsLayout.astro
title: Quick start
description: Install licence_audit, inspect your locked dependencies, create a policy, and enforce the policy.
---

`licence_audit` is a small CLI that audits the licences used by your Gleam
project's locked dependencies. It reads `manifest.toml` and gets licence
metadata from checksum-verified locked Hex archives. It reports the resolved
dependency tree, creates a CycloneDX SBOM, and checks for known vulnerabilities.

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

To pin a version, replace `latest` with an exact release tag (`vX.Y.Z`).
Choose a tag from the [latest published release][latest-release]. mise selects
the self-contained archive for your operating system and architecture.
You do not need Erlang/OTP. For source build instructions, refer to [DEV.md][dev].

## Standard workflow

Inspect the dependencies, create a policy, and enforce the policy.

```sh
# 1. Create manifest.toml and report the dependency tree
gleam deps download
licence_audit report

# 2. Select the licences to allow or deny
licence_audit update

# 3. Return a failure if the policy has a violation
licence_audit check
```

The `licence_audit report` command reports policy findings without enforcing
them and returns exit code `0` when the scan completes. An incomplete licence report
caused by unavailable or invalid package metadata returns `2`. The `check`
command also returns `1` when it finds a policy violation.

A bare `licence_audit` runs the same non-enforcing report. Both forms accept
the same scan options. Use `licence_audit --help` to show help without
reading project files, opening caches, or making network calls.

See [configuration discovery](/docs/configuration#discovery) for how the
manifest selects the project and policy file.

Reports, `check`, and `vulns` include all locked dependencies by default.
Use `--scope=prod` to select production dependencies, including shared
transitive dependencies:

```sh
licence_audit --scope=prod
licence_audit check --scope=prod
licence_audit vulns --scope=prod
licence_audit notices --scope=all
```

`notices` defaults to production scope; `--scope=all` adds development
dependencies. `sbom` always keeps the full graph. See the
[scope migration notes](/docs/compatibility#pre-10-dependency-scope-migration)
if you used `--prod-only` or `--include-dev`.

## Optional GitHub Actions usage

Use mise in GitHub Actions to install the same native binary as a local
install. We recommend native binaries for CI because they include the Erlang
runtime. For a Gleam project, set up Gleam first so `manifest.toml` exists.
The example selects OTP 28 for the job instead of relying on the project's
OTP version.

Replace `vX.Y.Z` below with the tag from the
[latest published release][latest-release].
Keep an exact tag in CI and update it after testing a newer release. mise's
[GitHub backend](https://mise.jdx.dev/dev-tools/backends/github.html#verification)
checks release digests or published checksums and verifies available GitHub
artifact attestations. It does not require a release to have attestations.

```yaml
name: licence audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  licence-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: tylerbutler/actions/setup-gleam@v1
      - uses: erlef/setup-beam@v1
        with:
          otp-version: "28"
      - uses: jdx/mise-action@v3
        with:
          install: false
      - run: mise exec github:tylerbutler/licence_audit@vX.Y.Z -- licence_audit check
        env:
          MISE_GITHUB_TOKEN: ${{ github.token }}
```

## Commands

| Command | What it does |
|---|---|
| [`check`](/docs/check) | Report metadata and enforce the licence policy. Returns a nonzero exit code for violations. |
| [`notices`](/docs/notices) | Create a third-party licence notices file for a release. Does not evaluate policy. |
| [`sbom`](/docs/sbom) | Create a CycloneDX 1.6 JSON SBOM. Does not evaluate policy. |
| [`update`](/docs/update) | Select licences and write a policy to `gleam.toml`. |
| [`vulns`](/docs/vulns) | Report known vulnerabilities from OSV.dev. Does not evaluate policy. |

### Flag values and aliases

Use `--flag=value` or `--flag value` for flags that take a value.
For example, `licence_audit sbom --output -v` writes to a file named `-v`;
it does not enable verbose output. Values can contain `=`, and you can use
`--output=--colour` for a file named `--colour`.

Use `-h`, `-q`, and `-v` as options for help, quiet output, and verbose output.
Use `--colour` as an alias for `--color`. These aliases keep their literal
text when you supply them as flag values. Do not use a `--` separator or
positional arguments.

## Output, colours, and exit codes

Reports and gate verdicts go to **stdout**. Progress, warnings, and operational
errors go to **stderr**. `--quiet` hides INFO and WARN messages, but never errors.
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
`CI`, and `COLORTERM`, and detects terminal support separately for stdout and
stderr. Explicit `always` and `never` values override environment settings for
report colours and stderr progress messages, including warnings and deferred
errors, on every command.

SBOM JSON and notice payloads stay plain in every color mode, including
`always`. Use `--help` or `-h` with any command. `--version` is available only
at the root.

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

`licence_audit` stores cache families below one application root:
`${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/`. Use `--cache-dir=DIR`
to select a root for metadata, locked-source metadata, notice materials, and
SPDX text. An explicit root takes precedence over environment discovery.
Use `--no-cache` to bypass reads and writes without deleting entries.
When neither `XDG_CACHE_HOME` nor `HOME` has a nonempty value on Windows,
the root is `%LOCALAPPDATA%\licence_audit\Cache\`, as resolved
by Erlang/OTP's user cache directory. A nonempty `XDG_CACHE_HOME` takes
precedence over `HOME` on all platforms.
Licence reports, `check`, and `update` share the immutable metadata cache with
`sbom --reproducible`. Each key includes the package name, locked version, and
archive checksum. These entries do not expire. The first scan downloads each
locked tarball, which is larger than an API response; later scans reuse its
verified metadata.

Optional API enrichment for default SBOMs and notices uses separate
`name@version` entries with a 7-day lifetime. API licences do not determine
licence report, check, or update results. `--no-cache` bypasses both entry types
and still requires checksum verification for licence scans.

The cache is shared across projects and commands. Concurrent commands can
share the cache. In CI, restore and save the
cache directory between jobs, for example with `actions/cache`,
`--cache-dir=.hex-cache`, and `.hex-cache/` as the path to save. Use
`--verbose` to see cache hits and misses.

The root contains versioned family directories:

- `hex-v2/`: Hex API metadata and checksum/commit-keyed locked-source metadata.
- `notices-v3/`: package and source materials, including repository resolutions.
- `spdx-v1/`: pinned SPDX indexes and canonical licence/exception text.

The versioned directories are internal storage details, not CLI options.
Future local publication verification will use this root too. This release
does not add publication verification or change cache freshness rules.

Each family contains one JSON file for each entry. A command writes
each entry to a temporary file and then renames it, so other commands never
read a partial entry. You can copy the cache directory at any time. To clear
the cache, delete the directory.

The cache fills on first use. `licence_audit` does not read or change old
`.dets` or `.sqlite3` cache files. You can delete them. If `--cache-dir`
points to a file, the command warns and continues without caching.

**Migration:** replace `--cache-path=.hex-cache/hex-v2` with
`--cache-dir=.hex-cache`. The old flag is rejected. Compatible metadata and
immutable materials remain usable in their existing versioned directories.
Pinned SPDX entries in `notices-v3/` are copied into `spdx-v1/` on a hit.
Other incompatible layouts are cache misses; no repair or deletion is required.

`licence_audit` caches each successful lookup when it completes. A later
lookup failure keeps earlier entries, and the audit continues with the
remaining packages. The cache excludes failed lookups. Failed archive
downloads, checksum verification, or metadata decoding cannot fall back to API
licences. Optional API enrichment can use an older API entry if a refresh fails.

If a cache operation fails, `licence_audit` continues the audit and writes a
warning to stderr. It does not cache OSV advisories.

Hex API network errors include the request URL and available DNS, connection,
or TLS details for IPv4 and IPv6. API request timeout errors include the
5000 ms limit. Archive downloads have a 30-second timeout.

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
and are identified as skipped. Reports, licence checks, and update discovery
use the `licenses` declarations in the locked archive's `metadata.config`.
The checksum must match `outer_checksum` in `manifest.toml`.

A missing or invalid checksum, checksum mismatch, unreadable archive, or
missing or invalid required metadata returns exit code `2`. An empty declared
licence list is valid metadata; licence policy evaluation decides its verdict.
Run `gleam deps download` to create a lockfile with checksums. The standalone
`vulns` command needs package identities, not archive checksums.

These declarations describe the locked release. They do not replace a legal
review or an inspection of licence text in source files.

## Root usage and flags

This section is generated from the CLI. Use `licence_audit --help` for the
options available in your installed version.

`--help` and `-h` show help for the root command or a subcommand, for example
`licence_audit sbom -h`. `--version` belongs to the root command:
use `licence_audit --version`, not `licence_audit sbom --version`.

<!-- cli-reference -->
Report Hex package licences without enforcing policy findings. Operational failures exit 2. Use `check` to enforce a licence policy.

**Usage:**

```
licence_audit (check | notices | report | sbom | update | vulns) [--flags]
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
| `--version` | `BOOL` | `false` | Print the installed version |
<!-- cli-referencestop -->

[releases]: https://github.com/tylerbutler/licence_audit/releases
[latest-release]: https://github.com/tylerbutler/licence_audit/releases/latest
[mise]: https://mise.jdx.dev/
[dev]: https://github.com/tylerbutler/licence_audit/blob/main/DEV.md
[apm]: https://github.com/microsoft/apm
