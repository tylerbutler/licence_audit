# licence_audit

[![CI](https://github.com/tylerbutler/licence_audit/actions/workflows/ci.yml/badge.svg)](https://github.com/tylerbutler/licence_audit/actions/workflows/ci.yml)
[![Publish](https://github.com/tylerbutler/licence_audit/actions/workflows/publish.yml/badge.svg)](https://github.com/tylerbutler/licence_audit/actions/workflows/publish.yml)

`licence_audit` is a simple CLI for checking the licences used by your Gleam project's locked dependencies.

It helps you:

- review the licences declared by your locked Hex packages
- enforce a licence allow/deny policy in CI
- generate an SBOM for your dependency tree
- check for known vulnerabilities in your locked dependencies

It reads `manifest.toml`, fetches package licence metadata from Hex, and reports the licences declared by locked Hex dependencies. Non-Hex dependencies are skipped and counted in the summary.

## Installation

### GitHub Actions

Use the shared setup action to install the released escript in a workflow. If
your workflow only needs to run an existing `manifest.toml`, the action can set
up Erlang/OTP 28 before downloading `licence_audit`.

```yaml
- uses: tylerbutler/actions/setup-licence-audit@v1
  with:
    version: v1.0.0
- run: licence_audit check
```

For a Gleam project workflow, set up Gleam first so `manifest.toml` exists, then
disable the duplicate Beam setup:

```yaml
- uses: tylerbutler/actions/setup-gleam@v1
- uses: tylerbutler/actions/setup-licence-audit@v1
  with:
    version: v1.0.0
    setup-beam: "false"
- run: licence_audit check
```

### Manual installation

Prebuilt escript archives are attached to each
[GitHub Release](https://github.com/tylerbutler/licence_audit/releases). The
archive contains the `licence_audit` escript and runs on any platform with a
compatible Erlang/OTP runtime.

Download the archive for your platform, extract it, and place `licence_audit`
somewhere on your `PATH`.

To build from source, see [DEV.md](./DEV.md).

## Quick start

If you just want the default report for your project:

```sh
gleam deps download
licence_audit
```

Once you know which licences appear in your tree, capture your policy by
running the interactive updater. It writes `allow` / `deny` lists to
`[tools.licence_audit]` in `gleam.toml`:

```sh
licence_audit update
```

If you want to fail CI when a licence violates that policy:

```sh
gleam deps download
licence_audit check
```

This is the most common workflow for end users: inspect your dependency licences, capture an allow/deny policy with `update`, then add `check` to your CI pipeline to enforce it.

## Usage

Run the default inventory report from a Gleam project after dependencies have been downloaded and `manifest.toml` exists:

```sh
licence_audit
```

The default mode reports package names, locked versions, and declared licences. It does not fail on policy violations unless you run the `check` subcommand.

By default, the CLI also writes high-level progress messages to stderr while it loads configuration, reads the manifest, fetches Hex package metadata, and completes the audit. Use `--quiet` to suppress progress output, or `--verbose` to include more detailed package-level progress.

Run an enforcing audit with policy checks:

```sh
licence_audit check
```

The `check` subcommand exits non-zero when a configured policy violation is found. You can also pass policy values on the command line:

```sh
licence_audit check --allow=Apache-2.0,MIT --deny=GPL-3.0-only
```

Useful options:

```sh
licence_audit --manifest=path/to/manifest.toml
licence_audit --config=path/to/gleam.toml
licence_audit --ignore-config
licence_audit --quiet
licence_audit --verbose
licence_audit --color=auto      # auto|always|never (default: auto)
licence_audit --no-cache
licence_audit --cache-path=path/to/cache
licence_audit --help
licence_audit -h
```

`--allow` and `--deny` are also accepted at the root level. They switch the
report into policy-status mode so you can preview what would pass or fail, but
the default command still exits 0. Run `licence_audit check` if you want policy
violations to fail the process.

### CLI reference

All commands accept `--help` and `-h`.

| Command | Purpose | Flags |
| ------- | ------- | ----- |
| `licence_audit` | Report locked Hex package licences. Exits 0 even when policy statuses show denials. | `--allow`, `--deny`, `--config`, `--manifest`, `--ignore-config`, `--quiet`, `--verbose`, `--color`, `--no-cache`, `--cache-path` |
| `licence_audit check` | Enforce the configured licence policy. | root flags, plus `--vulns`, `--vuln-severity` |
| `licence_audit update` | Interactively write `[tools.licence_audit]` policy. | `--config`, `--manifest`, `--ignore-config`, `--quiet`, `--verbose`, `--color`, `--no-cache`, `--cache-path` |
| `licence_audit sbom` | Generate a CycloneDX 1.6 JSON SBOM. | `--manifest`, `--quiet`, `--verbose`, `--no-cache`, `--cache-path`, `--output`, `--offline`, `--reproducible` |
| `licence_audit vulns` | Report known vulnerabilities from OSV.dev without enforcing them. | `--manifest`, `--quiet`, `--verbose`, `--color` |

Common defaults:

| Flag/config | Default | Notes |
| ----------- | ------- | ----- |
| `--manifest` | `manifest.toml` | Read from the current working directory unless a path is supplied. |
| `--config` | `./gleam.toml` | Must contain `[tools.licence_audit]` when required by `check`. |
| `--color` | `auto` | Valid values: `auto`, `always`, `never`. |
| `--vuln-severity` / `vuln_severity` | `high` | Valid values: `low`, `medium`, `high`, `critical`. Invalid values fail. |
| `--cache-path` | `${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/hex.dets` | Caches Hex licence metadata only. |

Output contract:

| Output | Stream |
| ------ | ------ |
| Human audit reports | stdout |
| `sbom` JSON without `--output` | stdout |
| `sbom --output=PATH` JSON | `PATH`; stdout is empty |
| Progress, warnings, and CLI/runtime errors | stderr |

### Updating licence policy

Interactively discover licences from the locked manifest and write the selected policy to `[tools.licence_audit]`:

```sh
licence_audit update
licence_audit update --config=path/to/gleam.toml
```

The `update` subcommand fetches package metadata, preselects any existing allow and deny entries from configuration, prompts for the licences to allow or deny, and writes the result back to `gleam.toml` unless `--config` points at another TOML file.

`update` requires an interactive terminal. If stdin is not interactive it exits
1 without writing. Cancelling the prompt exits 130. `--ignore-config` starts
from an empty policy instead of preselecting values from the existing config.

### Generating an SBOM

Generate a [CycloneDX 1.6](https://cyclonedx.org/) JSON Software Bill of
Materials from the project's `manifest.toml`:

```sh
licence_audit sbom                       # prints pretty JSON to stdout
licence_audit sbom --output=sbom.json    # writes compact JSON to a file
licence_audit sbom --offline             # skip Hex fetch, omit licence fields
```

The SBOM includes every locked dependency as a CycloneDX component with a
package URL (`pkg:hex/...` for Hex, `pkg:github/owner/repo@<commit>` for
GitHub git deps), a SHA-256 hash for Hex packages (from the lockfile's
`outer_checksum`), the package description, and declared licences fetched from
Hex. Each Hex component also carries `externalReferences`: a `distribution`
link to its `repo.hex.pm` tarball plus any `meta.links` (source repo, homepage,
docs) mapped to CycloneDX reference types. The root component is enriched from
`gleam.toml` with its description, declared licence, and repository URL. A
`dependencies` graph mirrors the dependency tree.

Licences are tagged `acknowledgement: "declared"` to record that they come from
the package's own metadata rather than from scanning its source. When a package
declares **multiple** licences they are emitted as separate licence entries:
Hex does not say whether the relationship is "AND" or "OR", so no SPDX
expression is synthesised that would assert an operator we cannot verify.

The `sbom` subcommand does not read licence policy and does not accept
`--config` or `--ignore-config`. It exits non-zero on I/O, manifest, or network
errors, **and** on any locked dependency whose source cannot be expressed as a
clean purl. Supported sources are `hex` and `git` with a `github.com`
repository; path dependencies, non-GitHub git deps, and any other source fail
with a clear error naming the offending package. `--offline` skips Hex licence
metadata fetches only; unsupported dependency sources still fail because the
SBOM would not have valid purls. (Contrast with `vulns`, which silently skips
unsupported sources.)

#### Reproducible output

By default each run emits a random `serialNumber` and a wall-clock `timestamp`,
so two SBOMs generated from the same dependency set never byte-compare equal.
Pass `--reproducible` to make the output deterministic:

```sh
licence_audit sbom --reproducible > bom.json
```

In this mode:

- the `serialNumber` is a `urn:uuid` derived from a SHA-256 hash of the BOM
  content — stable for a given dependency set, and changing only when the
  dependencies change;
- the `timestamp` comes from
  [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/docs/source-date-epoch/)
  when set, otherwise `1970-01-01T00:00:00Z`.

Components and `dependsOn` lists are always emitted in a stable sorted order
(independent of the flag). Deterministic output makes it practical to commit the
SBOM to source control and diff it in CI to catch dependency or licence drift.

### Validating the SBOM

The generated SBOM is checked against the official CycloneDX schema in CI so
schema regressions in the output fail the build. Two `just` tasks (tools
installed via `mise`) cover this:

```sh
just sbom-validate   # schema validation; fails on any error (runs in CI)
just sbom-score      # quality/completeness score (local only, informational)
just sbom-check      # both of the above
```

`sbom-validate` runs three independent validators —
[`cyclonedx-cli`](https://github.com/CycloneDX/cyclonedx-cli),
[`sbom-utility`](https://github.com/CycloneDX/sbom-utility), and cdxgen's
[`cdx-validate`](https://github.com/cdxgen/cdxgen) (schema + deep purl/reference
checks). `sbom-score` runs [`sbom-tools`](https://github.com/sbom-tool/sbom-tools)
and [`sbomqs`](https://github.com/interlynk-io/sbomqs). Only validation runs in
CI — scoring is a local-only convenience.

For `cdx-validate`, `--fail-severity critical` keeps its compliance scorecards
(OWASP SCVS, CRA) from gating CI on non-structural gaps such as "BOM is not
signed"; only a broken schema or failed deep check fails the build.

As of the latest run the SBOM scores **86.3 / 100 (grade B)** on `sbom-tools`
(licences 91.8/100), confirming the output is high quality. `sbomqs` reports a
lower **7.4 / 10 (grade C)** for two reasons, neither a real defect:

- its component-analysis category (malware / EOL checks) needs a third-party
  service and is always zero here; and
- `sbomqs` does not currently count component licences on CycloneDX **1.6**, nor
  when the `acknowledgement` field is present, so it reports "0 licences" even
  though every dependency carries a declared one — `sbom-tools` and all three
  validators read them correctly. This divergence is why schema validation, not
  any single quality score, is the CI gate.

### Checking for known vulnerabilities

Query the [OSV.dev](https://osv.dev/) database for known vulnerabilities
affecting the locked dependencies:

```sh
licence_audit vulns
```

The report lists each affected package with its OSV / GHSA / CVE
identifiers, a severity bucket (`critical`, `high`, `medium`, `low`, or
`unknown`), and a one-line summary. It ends with a tally of how many
packages were checked, how many had vulnerabilities, and how many were
clean. `vulns` does not evaluate licence policy and exits non-zero only on
I/O, manifest, or network errors — never on the mere presence of a
vulnerability. Packages with a `pkg:hex` or `pkg:github` purl are queried;
path deps and other unsupported sources are skipped and listed at the end
of the report.

Severity is taken from OSV's `database_specific.severity` field when
available and falls back to a coarse bucket derived from the CVSS vector.

OSV.dev is queried over HTTPS; an internet connection is required and
results are not cached on disk in this release. The CLI sends one
`POST /v1/querybatch` request and one `GET /v1/vulns/{id}` request per
unique advisory ID.

To enforce vulnerabilities as part of the policy gate, pass `--vulns`
to `check`:

```sh
licence_audit check --vulns
licence_audit check --vulns --vuln-severity=medium
```

`check --vulns` runs the licence audit first, then queries OSV.dev and
fails when any advisory's severity meets or exceeds the configured threshold.
It also exits non-zero if OSV.dev cannot be queried, because the vulnerability
gate could not be completed. Valid thresholds are `low`, `medium`, `high`
(default), and `critical`. Invalid values fail instead of falling back.
Advisories with unknown severity are reported but never trigger a failure. The
threshold can also be set in config:

```toml
[tools.licence_audit]
vuln_severity = "high"
```

CLI flags override the config value.

Example failure output:

```text
Vulnerability check (threshold: high):
...
Vulnerability check failed: one or more advisories at or above threshold severity.
```

### Report format

Each row is prefixed with a status glyph and indented to reflect the
dependency tree:

| Glyph | Meaning                                                          |
| ----- | ---------------------------------------------------------------- |
| `✓`   | licence allowed by policy (`check` only)                         |
| `✗`   | licence denied by policy (`check` only)                          |
| `?`   | no policy evaluated (default mode), or status unknown            |
| `·`   | package skipped (non-Hex source, e.g. `git` or path)             |

Default mode emits three columns when no policy is in scope: `Package`,
`Version`, `Licences`. As soon as a policy is configured (via
`[tools.licence_audit]` in `gleam.toml`, `--allow`/`--deny`, or running
`check`), a fourth `Status` column appears with values like `allowed`,
`denied: …`, or `skipped: …`. The default subcommand still exits 0 even
when statuses show denials; only `check` exits non-zero. Transitive
dependencies appear under their parent with a `├─`/`└─` tree prefix; there
is no separate "direct vs transitive" column. The audit always covers the
full resolved dependency tree.

Color is controlled by `--color` (`auto`, `always`, `never`). `auto` detects
stdout color support and honours standard color environment variables such as
`NO_COLOR`, `FORCE_COLOR`, `TERM`, `CI`, and `COLORTERM`. Pass
`--color=always` to force ANSI codes, or `--color=never` to force plain text.

## Policy configuration

Add a `[tools.licence_audit]` section to your project's `gleam.toml`:

```toml
[tools.licence_audit]
allow = ["Apache-2.0", "MIT"]
deny = ["GPL-3.0-only"]
```

Allow and deny lists are merged with any `--allow` and `--deny` CLI values. When running the `check` subcommand, an allow list means only those licences are accepted; a deny list rejects matching licences.

Use `--config=path/to/other.toml` to point at a different TOML file (it must still contain a `[tools.licence_audit]` section), or `--ignore-config` to use only CLI flags.

## Cache

Hex licence metadata is cached on disk between runs to keep repeated audits
fast. The default location is:

```
${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/hex.dets
```

Override it with `--cache-path=PATH`, or bypass the cache entirely with
`--no-cache`. `--no-cache` disables cache opening, reads, and writes for the
run. Cache failures (open, read, write) are non-fatal and never block an audit;
they are surfaced as warnings on stderr. OSV.dev vulnerability advisories are
not cached.

## CI example

Set up Gleam, install `licence_audit`, then run the audit. Pin `version` to the
release you want to run in CI.

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
          version: v1.0.0
          setup-beam: "false"
      - run: licence_audit check
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Command completed successfully. The default report command also uses 0 when policy statuses show denials. |
| `1` | Enforced gate failed (`check` policy violation or `check --vulns` advisory at/above threshold), invalid CLI usage, or `update` could not run non-interactively. |
| `2` | Input, config, manifest, decode, Hex, OSV, or SBOM generation/write error. |
| `130` | `update` was cancelled by the user. |

Per-command summary:

| Subcommand | Exit non-zero when… |
| ---------- | ------------------- |
| _(default)_ | I/O, config, manifest, Hex, or decode error |
| `check` | …above, missing policy, or any licence violates policy |
| `check --vulns` | …above, OSV.dev query failure, or any advisory meets/exceeds `--vuln-severity` |
| `update` | non-interactive stdin, write/config/input error, or user cancellation |
| `sbom` | I/O, manifest, network, decode, write, or unsupported dependency source error |
| `vulns` | I/O, manifest, network, or decode error; the presence of a vulnerability does *not* fail |

## Troubleshooting

- **`manifest.toml not found`** — run `gleam deps download` in the project
  first; the manifest is generated as a side effect of dependency
  resolution.
- **Hex fetch fails or times out** — Hex may be rate-limiting. Retry, or
  rerun with `--no-cache` removed so cached entries are reused.
- **`sbom` fails with "unsupported source"** — at least one locked dep
  comes from a path or non-GitHub git source. `sbom` requires every dep to
  resolve to a clean purl; remove or replace the dep before generating an
  SBOM. `sbom --offline` only skips Hex licence metadata fetches; it does not
  bypass purl validation.
- **OSV.dev unreachable** — `vulns` and `check --vulns` require network
  access to `api.osv.dev`. There is no on-disk cache for advisories.
- **No colors in CI logs** — `--color=auto` follows terminal/color detection
  and standard environment variables. Pass `--color=always` in CI if you want
  ANSI codes, or `--color=never` (or set `NO_COLOR=1`) to force plain text.

## Limitations

- Audits locked Hex packages listed in `manifest.toml`; run `gleam deps download` first.
- Non-Hex dependencies are skipped and counted in the report summary.
- Default mode reports only — run `check` to enforce licence policy.
  Vulnerability advisories are reported by `vulns` and can be added to the
  `check` gate via `--vulns`.
- Uses Hex package metadata for licences, not release metadata.

## Contributing

See [DEV.md](./DEV.md) for build instructions and contributor workflow.
