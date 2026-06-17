# licence_audit

A small CLI that audits the licences used by your Gleam project's locked
dependencies. Point it at a project, and it will:

- 📋 **report** the licences declared by your locked Hex packages
- 🚦 **preview or enforce** a licence allow/deny policy
- 📦 **generate** a CycloneDX SBOM for your dependency tree
- 📄 **bundle** release-ready third-party licence notices
- 🛡️ **check** locked dependencies for known vulnerabilities (OSV.dev)

It reads `manifest.toml`, fetches licence metadata from Hex, and reports on the
full resolved dependency tree. For audit reports, non-Hex dependencies are
skipped and named in the summary; `notices` handles supported source archives
and fails on unsupported sources.

## Install

### With mise

If you use [mise](https://mise.jdx.dev/), install `licence_audit` with the
`github:` provider:

```sh
mise use -g "github:tylerbutler/licence_audit@latest"
```

Replace `latest` with a release tag, such as `v0.3.0`, to pin a version. For a
project-local install, omit `-g`. The escript still needs Erlang/OTP 28.x or
newer on your `PATH`; if you manage Erlang with mise, install it too:

```sh
mise use -g erlang@28
```

### From a GitHub Release

Prebuilt escript archives are attached to each
[release](https://github.com/tylerbutler/licence_audit/releases). Download the
archive, extract it, and put `licence_audit` on your `PATH`. It runs on any
platform with Erlang/OTP 28.x or newer. Older OTP releases cannot reattach
stdin in raw mode, which breaks keyboard input for `licence_audit update`.

To build from source, see [DEV.md](./DEV.md).

## Quick start

The typical workflow is **inspect → capture a policy → enforce it when needed**:

```sh
# 1. Make sure manifest.toml exists, then see what's in your tree
gleam deps download
licence_audit

# 2. Interactively pick which licences to allow/deny.
#    Writes [tools.licence_audit] into gleam.toml.
licence_audit update

# 3. Fail on any violation
licence_audit check
```

The bare `licence_audit` command only reports — it never fails. Only `check`
exits non-zero on a policy violation.

## Commands

<!-- root -->
Reports Hex package licence metadata. It displays a summary of the licences for the project's dependencies. Use the `check` subcommand to enforce a licence policy, and the `update` subcommand to create a policy.

**Usage:**

```
licence_audit (check | notices | sbom | update | vulns) [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--allow` | `STRING_LIST` | `` | Allow licences, comma-separated |
| `--cache-path` | `STRING` | `__licence_audit_absent_string_flag__` | Override the licence metadata cache file location |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` | `__licence_audit_absent_string_flag__` | Read configuration from PATH |
| `--deny` | `STRING_LIST` | `` | Deny licences, comma-separated |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` | `__licence_audit_absent_string_flag__` | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk licence metadata cache |
| `--prod-only` | `BOOL` | `false` | Only audit production dependencies; ignore dev-dependency violations |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--verbose` | `BOOL` | `false` | Show detailed progress output |
<!-- rootstop -->

<!-- commands -->
## Subcommands

* [`licence_audit check`](docs/check.md) - Reports Hex package licence metadata and enforces the configured licence policy, exiting non-zero on violations.
* [`licence_audit notices`](docs/notices.md) - Generate a release-ready third-party licence notices text file from locked dependencies.
* [`licence_audit sbom`](docs/sbom.md) - Generate a CycloneDX 1.6 JSON SBOM from manifest.toml. Does not evaluate licence policy.
* [`licence_audit update`](docs/update.md) - Interactively review discovered licences and write an updated [tools.licence_audit] policy to gleam.toml.
* [`licence_audit vulns`](docs/vulns.md) - Report known vulnerabilities for locked dependencies using the OSV.dev database. Does not evaluate licence policy.
<!-- commandsstop -->

The sections below cover the *concepts* behind each command; reach for `docs/`
or `licence_audit <command> --help` when you need the exact flags.

## Enforce a licence policy

Define your policy in `gleam.toml`:

```toml
[tools.licence_audit]
allow = ["Apache-2.0", "MIT"]
deny  = ["GPL-3.0-only"]
```

An `allow` list means *only* those licences are accepted; a `deny` list rejects
matching licences. The easiest way to create this is `licence_audit update`,
which fetches metadata, preselects any existing entries, prompts you, and writes
the result back (comment-preserving). `update` needs an interactive terminal: it
exits `1` on non-interactive stdin and `130` if you cancel.

Then enforce it:

```sh
licence_audit check
licence_audit check --allow=Apache-2.0,MIT --deny=GPL-3.0-only   # ad-hoc policy
```

CLI `--allow`/`--deny` values merge with config. `check` exits non-zero on any
violation. Pass `--config=other.toml` to read policy from a different file (it
must still have a `[tools.licence_audit]` section) or `--ignore-config` to use
only CLI flags.

Use `--prod-only` when your gate should consider only production dependencies.
Dev-dependency licence violations are ignored, which is useful for CI checks
that should not fail on tooling-only packages.

> [!TIP]
> `--allow`/`--deny` also work on the bare command — they switch the report into
> a policy *preview* mode but still exit `0`. Use `check` when you want failures.

## Generate an SBOM

```sh
licence_audit sbom                     # pretty JSON to stdout
licence_audit sbom --output=sbom.json  # compact JSON to a file
licence_audit sbom --offline           # skip Hex fetch, omit licence fields
licence_audit sbom --reproducible      # deterministic output (see below)
licence_audit sbom --vulns             # embed OSV vulnerabilities (see below)
```

`sbom` emits a [CycloneDX 1.6](https://cyclonedx.org/) document. Every locked
dependency becomes a component with a package URL (`pkg:hex/...` for Hex,
`pkg:github/owner/repo@<commit>` for GitHub git deps), a SHA-256 hash for Hex
packages, the package description, declared licences, and external references
(tarball, source, homepage, docs). The root component is enriched from
`gleam.toml`, and a `dependencies` graph mirrors the tree.

Licences are tagged `acknowledgement: "declared"` (from package metadata, not
source scanning). Packages declaring **multiple** licences emit one entry each —
Hex doesn't say whether the relationship is AND or OR, so no SPDX expression is
synthesised.

`sbom` ignores licence policy. It **fails** on any dependency whose source can't
become a clean purl (path deps, non-GitHub git deps); only `hex` and GitHub
`git` are supported. `--offline` skips licence fetches but still validates purls.
(Contrast with `vulns`, which silently skips unsupported sources.)

**Embedded vulnerabilities.** `--vulns` queries OSV.dev (the same pipeline as the
standalone `vulns` command) and embeds the results into the document's CycloneDX
`vulnerabilities` array — one entry per advisory, each with its `id`, an `OSV`
source link, ratings (the raw CVSS vector and method when OSV reports one,
otherwise the severity bucket), and an `affects` list referencing the affected
components by `bom-ref`/purl. The result is a single VEX-style document that
tools like [Dependency-Track](https://dependencytrack.org/) can ingest directly.
Because it needs network access, `--vulns` cannot be combined with `--offline`.

**Reproducible output.** By default the `serialNumber` is random and the
`timestamp` is wall-clock, so two runs never byte-match. `--reproducible` makes
the `serialNumber` a content hash and takes the timestamp from
[`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/docs/source-date-epoch/)
(falling back to the Unix epoch) — making it practical to commit the SBOM and
diff it over time to catch dependency or licence drift.

**Validation.** The repository validates the generated SBOM against the official
CycloneDX schema. Three `just` tasks (tools installed via `mise`) cover this:

```sh
just sbom-validate   # schema validation
just sbom-score      # quality score (local only, informational)
just sbom-check      # both
```

Validation runs `cyclonedx-cli`, `sbom-utility`, and cdxgen's `cdx-validate`.
Scoring (`sbom-tools`, `sbomqs`) is local-only; note `sbomqs` under-counts
licences on CycloneDX 1.6, which is why schema validation — not any single
quality score — is the strict validation check.

## Generate release licence notices

```sh
licence_audit notices
licence_audit notices --output=THIRD_PARTY_LICENSES.txt
licence_audit notices --include-dev
```

`notices` creates a plain-text release artifact containing the actual licence
and notice files shipped by locked dependencies, not canonical SPDX text
inferred from identifiers. It defaults to production dependencies; pass
`--include-dev` to include development-only dependencies.

Use `notices` when you need a human-readable third-party licence bundle for a
release. Use `sbom` when you need machine-readable CycloneDX JSON. `notices` is
similar to npm's `generate-license-file`.

`notices` fails if selected dependencies lack a recognizable licence or notice
file, if a dependency source is unsupported, or if a network, archive,
checksum, or output write error occurs. Hex tarballs are verified against
`outer_checksum`.

## Check for vulnerabilities

```sh
licence_audit vulns
```

Queries [OSV.dev](https://osv.dev/) and lists each affected package with its
OSV/GHSA/CVE identifiers, a severity bucket (`critical`/`high`/`medium`/`low`/
`unknown`), and a one-line summary, ending with a checked/affected/clean tally.
`vulns` never fails on the *presence* of a vulnerability — only on I/O,
manifest, or network errors. Hex and GitHub deps are queried; other sources are
skipped and listed at the end. Severity comes from OSV's
`database_specific.severity`, falling back to the CVSS vector. Advisories are
fetched over HTTPS and are **not** cached.

To fail when vulnerabilities meet a severity threshold, add `--vulns` to
`check`:

```sh
licence_audit check --vulns
licence_audit check --vulns --vuln-severity=medium
```

This runs the licence audit, then queries OSV.dev and fails when any advisory's
severity meets or exceeds the threshold (`low`/`medium`/`high` (default)/
`critical`). Unknown-severity advisories are reported but never fail. It also
fails if OSV.dev can't be reached, since the vulnerability check couldn't complete. The
threshold can also live in config (CLI flags win):

```toml
[tools.licence_audit]
vuln_severity = "high"
```

## Output, colours & exit codes

**Streams.** Reports go to stdout; everything else to stderr:

| Output | Stream |
| ------ | ------ |
| Human audit reports | stdout |
| `sbom` JSON (no `--output`) | stdout |
| `sbom --output=PATH` | `PATH` (stdout empty) |
| Progress, warnings, errors | stderr |

Progress messages are written to stderr as the audit runs; use `--quiet` to
silence them or `--verbose` for package-level detail.

**Report format.** Rows are indented to reflect the dependency tree (`├─`/`└─`)
and prefixed with a status glyph:

| Glyph | Meaning |
| ----- | ------- |
| `✓` | licence allowed by policy (`check` only) |
| `✗` | licence denied by policy (`check` only) |
| `?` | no policy evaluated, or status unknown |
| `·` | package skipped (non-Hex source) |

The default report shows `Package`, `Version`, `Licences`. Once a policy is in
scope (config, `--allow`/`--deny`, or `check`) a `Status` column appears. Colour
is controlled by `--color`/`--colour` (`auto`/`always`/`never`); `auto`
honours `NO_COLOR`, `FORCE_COLOR`, `TERM`, `CI`, and `COLORTERM`.

**Exit codes.**

| Code | Meaning |
| ---- | ------- |
| `0` | Success (the default report uses `0` even when statuses show denials). |
| `1` | Enforced check failed (`check` violation, or `check --vulns` advisory at/above threshold), invalid usage, or `update` couldn't run non-interactively. |
| `2` | Input, config, manifest, decode, Hex, OSV, or SBOM error. |
| `130` | `update` cancelled by the user. |

## Caching

Hex licence metadata is cached on disk between runs:

```
${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/hex-v2.dets
```

Override with `--cache-path=PATH` or bypass with `--no-cache`. The filename is
version-suffixed so cache format bumps ignore stale data instead of reading it
back. Cache failures are non-fatal — they surface as stderr warnings and never
block an audit. OSV advisories are not cached.

## Troubleshooting

- **`manifest.toml not found`** — run `gleam deps download` first; the manifest
  is a side effect of dependency resolution.
- **Hex fetch fails or times out** — Hex may be rate-limiting; retry, or let
  cached entries be reused (don't pass `--no-cache`).
- **`sbom` fails with "unsupported source"** — a dep resolves to a path or
  non-GitHub git source. `sbom` needs a clean purl for every dep; `--offline`
  doesn't bypass this.
- **OSV.dev unreachable** — `vulns` and `check --vulns` need network access to
  `api.osv.dev`; there's no on-disk cache for advisories.
- **`update` does not react to keystrokes** — use Erlang/OTP 28.x or newer.
  Earlier OTP releases cannot reattach stdin in raw mode, so the interactive
  picker cannot receive keyboard input.
- **No colours in automated output** — pass `--color=always` or
  `--colour=always` to force ANSI codes, or `--color=never`/`--colour=never`
  (or set `NO_COLOR=1`) for plain text.

## Limitations

- Audits only locked **Hex** packages in `manifest.toml`; non-Hex deps are
  skipped and named in the summary.
- Uses Hex *package* metadata for licences, not per-release metadata.
- The default command reports only — run `check` to enforce policy, and add
  `--vulns` to fail on vulnerabilities.

## Optional GitHub Actions usage

If you want to wire `licence_audit` into GitHub Actions, use the shared setup
action. For a Gleam project, set up Gleam first so `manifest.toml` exists:

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
      - uses: tylerbutler/actions/setup-licence-audit@v1
        with:
          version: v0.3.0
          setup-beam: "false"
      - run: licence_audit check
```

## Contributing

See [DEV.md](./DEV.md) for build instructions and the contributor workflow.
