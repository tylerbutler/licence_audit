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
have to install Erlang/OTP on the target machine.

With [mise][mise], install directly from the `github:` provider:

```sh
mise use -g "github:tylerbutler/licence_audit@latest[asset_pattern=licence_audit,bin=licence_audit]"
```

Replace `latest` with a tag such as `v0.7.0` to select a fixed version. The
`asset_pattern` selects the escript asset. This asset requires Erlang/OTP 28.x
or newer on your `PATH`. For source build instructions, refer to
[DEV.md][dev].

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

The `licence_audit` command reports results and returns exit code 0. The
`check` command returns a nonzero exit code when it finds a policy violation.

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
| `·` | Command skips the package (non-Hex source) |

Use `--color` or `--colour` to control colour. The permitted values are `auto`,
`always`, and `never`. The `auto` value uses `NO_COLOR`, `FORCE_COLOR`, `TERM`,
`CI`, and `COLORTERM`.

The command uses these exit codes:

| Code | Meaning |
|---|---|
| `0` | Success. The default report uses `0` when statuses show denials. |
| `1` | Enforced check failure, invalid usage, or non-interactive use of `update`. |
| `2` | Input, config, manifest, decode, Hex, OSV, or SBOM error. |
| `130` | `update` cancelled by the user. |

## Compatibility

From version 1.0.0, the CLI and configuration follow the
[compatibility policy](/docs/compatibility). Read it for versioning rules,
stable interfaces, output guarantees, and exceptions for correctness fixes.
Gleam modules and human-readable report formatting are not supported
integration interfaces.

## Caching

`licence_audit` caches Hex licence metadata on disk between runs at
`${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/hex-v2.dets`. Override it with
`--cache-path=PATH`, or bypass it with `--no-cache`. If a cache operation
fails, `licence_audit` continues the audit and writes a warning to stderr. It
does not cache OSV advisories.

[releases]: https://github.com/tylerbutler/licence_audit/releases
[mise]: https://mise.jdx.dev/
[dev]: https://github.com/tylerbutler/licence_audit/blob/main/DEV.md
