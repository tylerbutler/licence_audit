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
```

`--allow` and `--deny` are also accepted at the root level for symmetry with the help output, but they have no effect outside the `check` subcommand. Run `licence_audit check` if you want policy to be enforced.

### Updating licence policy

Interactively discover licences from the locked manifest and write the selected policy to `[tools.licence_audit]`:

```sh
licence_audit update
licence_audit update --config=path/to/gleam.toml
```

The `update` subcommand fetches package metadata, preselects any existing allow and deny entries from configuration, prompts for the licences to allow or deny, and writes the result back to `gleam.toml` unless `--config` points at another TOML file.

### Generating an SBOM

Generate a [CycloneDX 1.5](https://cyclonedx.org/) JSON Software Bill of
Materials from the project's `manifest.toml`:

```sh
licence_audit sbom                       # prints pretty JSON to stdout
licence_audit sbom --output=sbom.json    # writes compact JSON to a file
licence_audit sbom --offline             # skip Hex fetch, omit licence fields
```

The SBOM includes every locked dependency as a CycloneDX component with a
package URL (`pkg:hex/...` for Hex, `pkg:github/owner/repo@<commit>` for
GitHub git deps), a SHA-256 hash for Hex packages (from the lockfile's
`outer_checksum`), and declared licences fetched from Hex. A `dependencies`
graph mirrors the dependency tree.

The `sbom` subcommand does not evaluate licence policy. It exits non-zero on
I/O, manifest, or network errors, **and** on any locked dependency whose
source cannot be expressed as a clean purl. Supported sources are `hex` and
`git` with a `github.com` repository; path dependencies, non-GitHub git
deps, and any other source fail with a clear error naming the offending
package. (Contrast with `vulns`, which silently skips unsupported sources.)

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
fails when any advisory's severity meets or exceeds the configured
threshold. Valid thresholds are `low`, `medium`, `high` (default), and
`critical`. Advisories with unknown severity are reported but never
trigger a failure. The threshold can also be set in config:

```toml
[tools.licence_audit]
vuln_severity = "high"
```

CLI flags override the config value.

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

Color is controlled by `--color` (`auto`, `always`, `never`). `auto` honours
the `NO_COLOR` environment variable but does **not** auto-detect a TTY —
pass `--color=never` (or set `NO_COLOR=1`) when redirecting to a file or
pipe.

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
`--no-cache`. Cache failures (open, read, write) are non-fatal and never
block an audit; they are surfaced as warnings on stderr.

## CI example

Download the `licence_audit` escript from a GitHub Release in your workflow,
then run the audit. Bump `VERSION` to the release you want to pin to, or
replace the URL with `releases/latest/download/...` to track the most recent
release automatically.

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
      - uses: erlef/setup-beam@v1
        with:
          otp-version: "27"
          gleam-version: "1.x"
      - name: Download licence_audit
        env:
          VERSION: v1.0.0
        run: |
          curl -fsSL -o licence_audit.tar.gz \
            "https://github.com/tylerbutler/licence_audit/releases/download/${VERSION}/licence_audit-${VERSION}.tar.gz"
          tar -xzf licence_audit.tar.gz --strip-components=1
          chmod +x licence_audit
          echo "$PWD" >> "$GITHUB_PATH"
      - run: gleam deps download
      - run: licence_audit check
```

## Exit codes

| Subcommand           | Exit non-zero when…                                                       |
| -------------------- | ------------------------------------------------------------------------- |
| _(default)_          | I/O, manifest, or network error                                           |
| `check`              | …above, **or** any licence violates policy                                |
| `check --vulns`      | …above, **or** any advisory meets/exceeds `--vuln-severity`               |
| `sbom`               | …I/O, manifest, or network error, **or** an unsupported dependency source |
| `vulns`              | …I/O, manifest, or network error (presence of a vulnerability does *not* fail) |

## Troubleshooting

- **`manifest.toml not found`** — run `gleam deps download` in the project
  first; the manifest is generated as a side effect of dependency
  resolution.
- **Hex fetch fails or times out** — Hex may be rate-limiting. Retry, or
  rerun with `--no-cache` removed so cached entries are reused.
- **`sbom` fails with "unsupported source"** — at least one locked dep
  comes from a path or non-GitHub git source. `sbom` requires every dep to
  resolve to a clean purl; either remove the dep or use `sbom --offline` if
  you only need the structural SBOM without licence fields.
- **OSV.dev unreachable** — `vulns` and `check --vulns` require network
  access to `api.osv.dev`. There is no on-disk cache for advisories.
- **No colors in CI logs** — `--color=auto` does not detect a TTY. Pass
  `--color=always` in CI if you want ANSI codes, or `--color=never` (or set
  `NO_COLOR=1`) to force plain text.

## Limitations

- Audits locked Hex packages listed in `manifest.toml`; run `gleam deps download` first.
- Non-Hex dependencies are skipped and counted in the report summary.
- Default mode reports only — run `check` to enforce licence policy.
  Vulnerability advisories are reported by `vulns` and can be added to the
  `check` gate via `--vulns`.
- Uses Hex package metadata for licences, not release metadata.

## Contributing

See [DEV.md](./DEV.md) for build instructions and contributor workflow.
