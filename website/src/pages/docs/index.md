---
layout: ../../layouts/DocsLayout.astro
title: Quick start
description: Install licence_audit, then inspect, capture a policy, and enforce it across your Gleam project's locked Hex dependencies.
---

`licence_audit` is a small CLI that audits the licences used by your Gleam
project's locked dependencies. It reads `manifest.toml`, fetches licence
metadata from Hex, and reports on the full resolved dependency tree — and it can
generate a CycloneDX SBOM and check for known vulnerabilities along the way.

## Install

The prebuilt archives attached to each [release][releases] are the fastest path.
Download the self-contained archive for your platform, extract it, and put
`licence_audit` on your `PATH`. These Queso-built executables bundle the Erlang
runtime, so Erlang/OTP does **not** need to be installed on the target machine.

With [mise][mise], install directly from the `github:` provider:

```sh
mise use -g "github:tylerbutler/licence_audit@latest[asset_pattern=licence_audit,bin=licence_audit]"
```

Replace `latest` with a tag such as `v0.7.0` to pin a version. The
`asset_pattern` here selects the bare escript asset, which still needs
Erlang/OTP 28.x or newer on your `PATH`. To build from source, see
[DEV.md][dev].

## The typical workflow

The rhythm is **inspect → capture a policy → enforce it when needed**.

```sh
# 1. Make sure manifest.toml exists, then see what's in your tree
gleam deps download
licence_audit

# 2. Interactively pick which licences to allow or deny
licence_audit update

# 3. Fail on any violation
licence_audit check
```

The bare `licence_audit` command only *reports* — it never fails. Only `check`
exits non-zero on a policy violation.

## Commands

| Command | What it does |
|---|---|
| [`check`](/docs/check) | Report metadata **and** enforce the licence policy, exiting non-zero on violations. |
| [`notices`](/docs/notices) | Bundle a release-ready third-party licence notices file. Does not evaluate policy. |
| [`sbom`](/docs/sbom) | Generate a CycloneDX 1.6 JSON SBOM. Does not evaluate policy. |
| [`update`](/docs/update) | Interactively review licences and write a policy into `gleam.toml`. |
| [`vulns`](/docs/vulns) | Report known vulnerabilities from OSV.dev. Does not evaluate policy. |

## Output, colours & exit codes

Reports go to **stdout**; progress, warnings, and errors go to **stderr**. Rows
are indented to reflect the dependency tree and prefixed with a status glyph:

| Glyph | Meaning |
|---|---|
| `✓` | Licence allowed by policy (`check` only) |
| `✗` | Licence denied by policy (`check` only) |
| `?` | No policy evaluated, or status unknown |
| `·` | Package skipped (non-Hex source) |

Colour is controlled by `--color` / `--colour` (`auto` \| `always` \| `never`);
`auto` honours `NO_COLOR`, `FORCE_COLOR`, `TERM`, `CI`, and `COLORTERM`.

Exit codes are predictable, which is the point in CI:

| Code | Meaning |
|---|---|
| `0` | Success (the default report uses `0` even when statuses show denials). |
| `1` | Enforced check failed, invalid usage, or `update` couldn't run non-interactively. |
| `2` | Input, config, manifest, decode, Hex, OSV, or SBOM error. |
| `130` | `update` cancelled by the user. |

## Caching

Hex licence metadata is cached on disk between runs at
`${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/hex-v2.dets`. Override it with
`--cache-path=PATH` or bypass it with `--no-cache`. Cache failures are
non-fatal — they surface as stderr warnings and never block an audit. OSV
advisories are **not** cached.

[releases]: https://github.com/tylerbutler/licence_audit/releases
[mise]: https://mise.jdx.dev/
[dev]: https://github.com/tylerbutler/licence_audit/blob/main/DEV.md
