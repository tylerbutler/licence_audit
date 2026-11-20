# licence_audit changelog

## v1.0.0-rc.4 - 2026-11-20

### Fixed

- Exclude test-only Erlang helpers from the shipped executable.

## v1.0.0-rc.3 - 2026-11-19

### Removed

- Remove `--allow` and `--deny` from licence reports and `check`. Put complete allow/deny lists in `[tools.licence_audit]` in TOML and select an alternate policy with `--config`; ad-hoc CLI policy widening is no longer supported. Reports can still run without policy, while licence enforcement requires a non-empty configured allow list.
- Remove `update --ignore-config`, including explicit boolean forms. `update` now creates missing policy sections in valid default and explicit targets without bypassing TOML, policy, or exception validation; clear preselected entries in the picker to start a new selection. Read-only commands keep `--ignore-config`.
- Replace `--prod-only` and `--include-dev` with `--scope=prod|all` on licence reports, `check`, `vulns`, and `notices`. Reports, checks, and vulnerability reports still default to all dependencies; notices still defaults to production dependencies. The removed flags, including boolean forms, are rejected. `sbom` keeps its full graph and `update` has no scope option.

### Added

- Include local path dependencies in CycloneDX `sbom` output with validated current metadata, dependency edges, scopes, and stable manifest-relative references. Reject stale root local dependency declarations before network requests or output writes. Require Hex publication verification in online, offline, and reproducible modes; add a Hex purl only for a confirmed published name/version while retaining local provenance without release checksums. Store permanent positive and 24-hour negative verification records under `--cache-dir`; `--no-cache` does not bypass verification.
- Add `licence_audit report` as an explicit form of the default non-enforcing licence report. Bare invocation and root scan flags remain supported, with the same report options, findings, and operational exit codes.

### Changed

- Make `sbom --offline` prohibit network access while retaining required locked metadata, local publication verification, and requested pinned SPDX text. Warm-cache online and offline reproducible runs use the same evidence; missing required cache entries or `--no-cache` return exit 2 instead of omitting evidence.
- Replace `--cache-path` with `--cache-dir`, one application root for metadata, immutable notice materials, and pinned SPDX text. An explicit root takes precedence over environment defaults; `--no-cache` bypasses storage without deleting entries. Existing compatible versioned caches remain reusable.
- Replace `check --vulns` with `--checks=licences|vulns|all` (default `licences`). Use `check --checks=all` to keep combined enforcement, or `check --checks=vulns` for an OSV-only gate that does not require or enforce licence policy or fetch licence metadata. Standalone `vulns` and `sbom --vulns` are unchanged.
- Reserve exit code `1` for enforced gate failures. CLI usage errors, including non-interactive `update`, now exit `2`; cancellation remains `130`. Reject enabled `--ignore-config` with `--config` and enabled `--no-cache` with `--cache-dir` on commands that accept both flags. Remove one flag from each pair; explicit `=false` remains valid.

### Fixed

- Exclude symbolic links from local `notices` source traversal on Windows by using the native file type instead of POSIX mode bits.
- Handle Git package subdirectories correctly in mixed local SBOM workspaces and accept local packages declared in `[dev_dependencies]` with optional scope.
- Keep deny rules selected in `update` and merge equivalent SPDX spellings without merging case-distinct custom references.
- Let `check --checks=vulns` and `check --checks=all` use `--vuln-block-unknown=false` to override configured `vuln_block_unknown = true`. Omitted flags retain the configured value; severity threshold precedence is unchanged.
- Make `sbom --licence-text` the primary spelling and keep `--license-text` as a supported alias, with the same boolean and repeated-flag behavior.
- Name invalid allow/deny fields and entries, and preserve OSV transport failure reasons with the shared Hex HTTP formatter.
- Preserve cache read warnings for blocked Windows parent paths and prevent scratch-file leaks during concurrent cache replacement.
- Preserve literal values such as `-v`, `-q`, `-h`, and `--colour` after value-taking flags, including `sbom --output -v`, while retaining option aliases.
- Query OSV with the locked Git commit only, while retaining full subdirectory purls in reports and SBOM references.
- Refuse policy replacement on macOS when an ACL is present or access-rule inspection fails, leaving the original file and its access rules intact.
- Reject malformed Hex SHA-256 checksums and missing root or transitive lockfile targets before `sbom` writes output; preserve existing artifacts on failure.
- Reject stale `update` selections when allow or deny rules change, and preserve concurrent edits to unrelated settings.
- Reject `update` targets beneath an existing non-directory before fetching metadata or opening the picker on Windows.
- Require Gleam 1.19.2 or newer for source builds to preserve strict, correct Hex publication verification in `sbom`.
- Use checksum-verified locked Hex archive licence declarations for reports, `check`, and `update`, with immutable cache reuse and no API licence fallback.
- Use locked source licence declarations for notices, exclude local build output, and resolve repository fallback tags without accepting branches or old ambiguous cache entries.
- Use matching affected-package OSV scores in vulnerability reports, checks, and SBOM ratings without mixing package or version severities.

## v1.0.0-rc.2 - 2026-11-14

### Fixed

- Fix `sbom --license-text --cache-path` to keep SPDX text in the default versioned notice cache and apply the custom path only to metadata.
- Fix `sbom` output: omit false BOM author attribution, preserve single SPDX expressions, and include the timestamp in reproducible serial numbers.
- Fix `vulns` rejecting Hex manifest entries without `outer_checksum`; use the same identity loader as `check --vulns` while keeping SBOM checksum validation.
- Make `--color` and `--colour` control stderr progress and diagnostics on every command. Explicit `never` suppresses color even with `FORCE_COLOR`; `always` forces color even with `NO_COLOR`. JSON and notice payloads remain plain.
- Make licence exception selectors ignore ordinary SPDX identifier case and token whitespace, matching licence policy rules. Reject duplicate selectors after normalization while preserving custom reference case and exact package scope.
- Network-backed commands use IPv4 without a warning when the IPv6 DNS lookup finds no AAAA record; connection failures and timeouts still produce warnings.
- Report valid CVSS scores of `0.0` as `none` in `vulns`, `check --vulns`, and `sbom --vulns`; never block these ratings, even with a low threshold and unknown-severity blocking.
- Use the Windows user cache directory for CLI metadata and notices when `XDG_CACHE_HOME` and `HOME` are unset or empty. Preserve `--cache-path` and existing environment overrides.

## v1.0.0-rc.1 - 2026-11-08

### Breaking

- Declare the `licence_audit` CLI stable with the 1.0 release.

### Fixed

- Correct production dependency scope in check, SBOM, notices, and vulns when gleam.toml has no dependencies table; reject invalid or unreadable scope configuration while retaining the missing-file fallback.
- Decode TOML string escapes in project metadata and preserve array comments when `update` edits policies, including exceptions-only and inline-table configurations.
- Limit source archives used by `notices` and reproducible `sbom` metadata to 64 MiB per download and 256 MiB of tar data per extraction. Stop oversized downloads and gzip inflation before collecting the full archive.
- Make `notices` use the same SPDX expression syntax as `check`: handle tabs and line breaks correctly and reject malformed expressions before requesting canonical licence text.
- Respect Git dependency package subdirectories in `sbom --reproducible` metadata and `notices` licence lookups, cache keys, and SBOM package URLs.

## v1.0.0-rc.0 - 2026-11-07

### Breaking

- Declare the `licence_audit` CLI stable with the 1.0 release.

## v0.15.0 - 2026-11-06

### Added

- Add `-q` for `--quiet` on every command, `--color`/`--colour` on `sbom` and `notices` with plain payloads, `--config`/`--ignore-config` on `notices`, and `--prod-only` on `vulns`.

### Changed

- Remove the ineffective `vulns --no-cache` flag before 1.0. The `vulns` command queries OSV directly and does not use an on-disk cache.
- Require a non-empty `allow` list for `check`, including `check --vulns`. Keep `deny` as an exact-match override without licence variant equivalence. Warn when `update` saves an empty allow list.
- Store the on-disk caches as one JSON file per entry, not as SQLite databases. The CLI no longer has native dependencies: escripts no longer need the `sqlite_native/` directory, and cache paths can contain non-ASCII characters and are no longer limited to 504 bytes on Linux. `--cache-path` now names the metadata cache directory, for example `.hex-cache/hex-v2`. The default caches are `hex-v2/` and `notices-v3/` below `${XDG_CACHE_HOME:-$HOME/.cache}/licence_audit/`. The caches refill on first use; you can delete old `.sqlite3` files.

### Fixed

- Explicit `--config` files without `[tools.licence_audit]` now fail with exit 2 and a file-specific error, even when CLI flags supply a policy.
- Fix `notices` for Gleam local path dependencies by recognizing `source = "local"` in the manifest; retain `source = "path"` as an alias.
- Keep `check` gate verdicts on stdout without duplicate stderr errors, and send OSV request failure diagnostics to stderr even with `--quiet`.
- Map unexpected Erlang exceptions to CLI exit code `2` with a diagnostic instead of a raw crash; keep policy and usage failures at exit code `1`.
- Reject `check --vuln-severity` and `--vuln-block-unknown` without enabled `--vulns` as usage errors instead of silently skipping the vulnerability scan.
- Reject unknown policy and notices configuration keys and malformed SPDX expressions in config and CLI allow/deny entries with exit code 2.

## v0.14.0 - 2026-10-29

### Added

- Add `sbom --license-text` to embed canonical SPDX licence text for recognised IDs without changing default output.
- Add `include` and `exclude` filters under `[tools.licence_audit.notices]`. Apply them before metadata, source, and cache access, and reject names absent from the lockfile. Projects without a `[dependencies]` table now require `notices --include-dev` to include development dependencies.

### Changed

- Replace the on-disk metadata and notice caches with SQLite WAL, storing metadata and its timestamp in one atomic write. New `.sqlite3` caches refill on first use; the command does not import or change existing DETS files. Cache paths must be ASCII; Linux absolute database paths must not exceed 504 bytes (#168). Escript caching requires `sqlite_native/` beside the executable. Busy cache operations report a deferred warning without discarding fetched results. Bare escripts and installations with missing or unloadable SQLite native libraries run without caching and report a deferred warning. Use `--no-cache` to skip native-library loading.

## v0.13.2 - 2026-10-25

### Fixed

- Fix `sbom --reproducible` metadata decoding for quoted UTF-8 and numeric Hex binary literals; reject unsupported literals and ignore incomplete legacy immutable cache entries.
- Include application dependency notices and complete Slate attribution in release archives and the bare escript. Generate native runtime attribution from the built OTP, Queso, and toolchain inputs, and verify required notice contents in staged archives.
- Keep metadata-fetch failure trees visible beside policy failures in `check`, including with `--quiet`.
- Keep valid Git vulnerability queries in `check --vulns` when an unrelated Hex checksum is missing or malformed.
- Make `update` replace policy files atomically so interrupted writes leave the original configuration intact, while preserving permissions, ownership, comments, and unrelated TOML.
- Preserve Unicode in `XDG_CACHE_HOME` and `HOME` when the CLI resolves its cache directory, and handle environment conversion failures without crashing.
- Prevent repeated cache lock waits across dependency fetches; skip busy caches with a nonfatal warning.
- Ignore blank licence files and attribution-only files in SPDX-like paths in `notices`; use usable fallbacks and refresh stale material caches.
- Reject nested or dotted subfields for reserved policy settings, including empty descendant tables and nested exception expiry settings, instead of silently treating them as absent.
- Return exit code `2` for incomplete licence reports and `update` TOML edit/write failures. Report-only findings still exit `0`; optional advisory details and default SBOM enrichment remain non-fatal. Scripts must handle the changed report (`0` to `2`) and update (`1` to `2`) failure codes.
- Send fatal CLI diagnostics to stderr while keeping gate-failure reports on stdout and failed SBOM output empty.

## v0.13.1 - 2026-10-20

### Fixed

- Evaluate SPDX licence expressions in policy checks, preserve scoped exceptions for required terms, and reject malformed expressions even with a deny-only policy.
- Use OSV commit queries for GitHub dependencies in `vulns`, `check --vulns`, and `sbom --vulns` so affected commits do not appear clean.

## v0.13.0 - 2026-10-16

### Changed

- Bundle the CLI argument parser instead of downloading it from Git, and exclude Markdown documentation tooling from production builds.
- Change the on-disk cache format while preserving safe sharing between concurrent CLI runs. In CI, save the parent cache directory (for example, `.hex-cache/`) instead of a `*.entries/` subdirectory. Keep the bundled `slate_native/` directory beside the escript when you install or move it.

### Fixed

- Remove internal sentinel defaults from CLI documentation and preserve literal optional path values with native glint optional flags.

## v0.12.2 - 2026-10-11

### Fixed

- Extract only selected licence and notice members from source archives, preserving root priority and nested fallback. Gzip archives are decompressed once before selection and extraction instead of twice.
- HTTP disconnects and other transport failures return normal diagnostics instead of crashing licence audits, OSV checks, or notice generation. TLS verification and the bounded IPv6 fallback remain enabled.
- `notices` reads only selected licence and notice files from local dependencies. Unreadable unrelated files and directories no longer block packages with root licence files, and symlink targets remain excluded.
- Prevent concurrent CLI processes from losing shared cache entries by publishing per-entry files atomically under `<cache-path>.entries`. Legacy DETS files remain untouched; invalid UTF-8 cache entries produce warnings and are refetched.
- Resolve Windows manifest, dependency, and cache paths with the Hex `filepath` package, including drive-qualified and network-share paths, without custom path FFI.
- `update` preserves existing project configuration when a file read fails, including after policy selection and with `--ignore-config`. Read failures return exit code 2 instead of replacing the file with an empty policy.
- `vulns` fetches each shared OSV advisory once per command, including failed lookups, while preserving per-package findings and exception decisions.

## v0.12.1 - 2026-09-15

### Fixed

- Make `sbom --reproducible` read metadata from checksum-verified Hex archives and commit-pinned Git archives, omit mutable publisher data, and reject `--vulns`.

## v0.12.0 - 2026-09-13

### Added

- Add scoped policy exceptions with review reasons, UTC expiry, and visible licence and advisory decisions in `check` and `vulns` (#95).

## v0.11.1 - 2026-09-06

### Fixed

- Restore bounded IPv6 probing and remembered IPv4 fallback for Hex metadata and OSV requests, preventing repeated timeouts on networks with broken IPv6.

## v0.11.0 - 2026-09-06

### Changed

- Reuse cached Hex metadata for 7 days instead of 24 hours to reduce requests across audits and other commands. Use `--no-cache` to fetch fresh metadata.

### Fixed

- Show the request URL and available DNS, connection, TLS, and timeout details when Hex metadata requests fail. Include the package and failure reason in audit and `update` progress errors.

## v0.10.2 - 2026-09-06

### Fixed

- Fix self-contained binaries crashing on Hex and OSV HTTP requests because required OTP applications were not started.

## v0.10.1 - 2026-09-05

### Fixed

- Include the Apache-2.0 licence text in source and platform release archives.

## v0.10.0 - 2026-08-29

### Added

- Add a root `--version` flag that prints the installed build version.

### Changed

- Remove the internal `gen-docs` maintenance command from the public CLI.
- The `spruce` dependency now tracks the `tylerbutler/spruce` Git main branch; styled output is unchanged.

### Fixed

- Calculate fallback severity from complete CVSS v2, v3, and v4 vectors, so critical OSV advisories are not missed when a database-specific severity is absent.
- Embed the licence_audit build version at compile time and use it for CycloneDX `metadata.tools[].version` in `sbom` output. Previously the tool read `gleam.toml` from the current working directory, so auditing another project could leak that project's version into the tool metadata instead of licence_audit's own.
- Fail `check --vulns` with exit code 2 when an OSV advisory detail lookup fails, instead of treating it as a non-blocking unknown-severity placeholder. The failing advisory ID and failure reason are reported.
- Fail SBOM generation when project gleam.toml metadata is missing, unreadable, or invalid.
- Fix audit, update, `sbom`, and `vulns` project metadata resolution for manifests outside the current directory.
- Make `check --vulns` query supported GitHub dependencies and report unsupported sources.
- Make `sbom` report serial-number generation failures instead of crashing.
- Recognise dual-licence file names such as `LICENSE-MIT` and `LICENSE-APACHE` as licence text, so `notices` uses a package's root licence files instead of falling back to nested or vendored copies.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
and is generated by [Trellis](https://trellis.tylerbutler.com).


## v0.9.0 - 2026-08-21
### Added
* Added `check --vulns --vuln-block-unknown` and `vuln_block_unknown = true` policy support for optionally blocking advisories without a known severity.
### Changed
* Documented that `licence_audit sbom` reports metadata-derived declared licences and delegates concluded licence and copyright evidence to dedicated source scanners.
### Fixed
* Fixed `sbom` output to emit dependency scope through the native CycloneDX `scope` field instead of a custom property.

## v0.8.0 - 2026-07-19
### Added
* Added a `notices` command that generates a release-ready `THIRD_PARTY_NOTICES`-style file from locked dependencies, grouping shared licence text while preserving package-specific `NOTICE` and `COPYING` content. It supports GitHub, Codeberg, and GitLab sources, falls back to canonical SPDX text when needed, caches results across runs, and writes to stdout or `--output PATH`; use `--no-cache` to bypass caching.
* Added `-v` as an alias for the global `--verbose` flag and detailed `notices` progress showing per-package source selection, licence-file discovery, and processing steps.

## v0.7.0 - 2026-07-18
### Added
* Added self-contained release archives for Linux (glibc and musl), macOS, and Windows x86_64 alongside the existing escript artifacts.
* SBOM generation now enriches git-sourced dependencies with descriptions, licences, and repository links, and warns when package metadata is unavailable.
### Fixed
* SBOM generation now preserves cached package metadata during transient Hex failures and warns when metadata is stale or unavailable.
* Network-backed commands no longer incur repeated delays when IPv6 is unavailable; they fall back to IPv4 after one failed attempt and emit a warning.

## v0.6.0 - 2026-06-19
### Changed
* Updated tomlet to add support for TOML 1.1.

## v0.5.0 - 2026-06-17
### Changed
* Direct dependencies on `envoy`, `gleam_regexp`, and `youid` were removed in favor of standard string parsing and small Erlang FFI helpers.
* The sbom command now writes formatted JSON to output files.

## v0.4.0 - 2026-06-16
### Changed
* SBOM output now emits canonical (lowercased) `pkg:hex` and `pkg:github` purls, recognises the SPDX licence identifiers supported by CycloneDX 1.6 (emitting `license.id` only for schema-valid identifiers), adds `$schema`, adds a primary-component identifier when available, omits empty component versions, and de-duplicates declared licences.
* The `spruce` dependency now resolves to the published Hex package instead of a Git revision.
### Fixed
* Prevent `update` from silently corrupting `gleam.toml` when an existing `allow`/`deny` array line has a trailing comment containing a quote, or when a key of the same name exists in another table. The array rewrite is now scoped to the `[tools.licence_audit]` table and returns an error instead of writing a bogus value.
* `check --prod-only --vulns` now restricts the vulnerability gate to production dependencies, so dev-only advisories no longer fail the gate or appear in output. The prod-only skipped-package summary now matches the rendered tree.
* OSV vulnerability queries now follow `next_page_token` pagination with a page-count guard so vulnerabilities are no longer under-reported for heavily-affected packages without risking unbounded pagination, and CVSS 4.0 plus bare CVSS 2.0 vectors are now mapped to a severity bucket instead of Unknown.
* The on-disk Hex cache no longer serves a stale `publisher` value indefinitely; cached enrichment entries now expire after 24 hours.
* Report output no longer emits trailing whitespace on dependency rows in the default view, and tree column widths now match the rendered indentation when non-Hex intermediate dependencies are skipped.
* The interactive `update` picker now restores the terminal (raw mode and cursor) on all exit paths including panics, redraws correctly when its help line or labels wrap on narrow terminals, and no longer loops silently on repeated read errors.
* CI now regenerates the checked-in SBOM and fails when `dist/sbom.json` has drifted from the current source and lockfile.

## v0.3.0 - 2026-06-08
### Changed
* Migrate terminal styling in the colour and progress modules to the spruce terminal-UI kit (added as a git dependency); spruce wraps the same gleam_community_ansi styling, so output is unchanged. Dropped the now-transitive direct gleam_community_ansi dependency.
* Replace the glam pretty-printer with plain string building for the licence report tree and vulnerability reports (output unchanged), and drop the glam dependency.
* Render the licence report section titles, vulnerability reports, and the vulnerability check gate with spruce styling (bold/dim text and rounded boxes); styling is colour-gated so plain-text output is unaffected.
* Upgrade the tomlet dependency to 1.1.2 and replace the local TOML array-editing workarounds with tomlet's native value accessors (table_keys, as_string, set_array); generated output is unchanged.
### Security
* Release attestations now also cover the bare `licence_audit` escript and the `checksums.txt` manifest (in addition to the archives), and the SBOM attestation is extended to the bare binary; install instructions document verifying the binary directly.

## v0.2.0 - 2026-06-05
### Added
* `sbom --vulns` queries OSV.dev and embeds the results into the generated CycloneDX document as a `vulnerabilities` array. Each advisory becomes one entry with its `id`, an `OSV` source link, ratings (the raw CVSS vector and method when OSV reports one, otherwise the severity bucket), and an `affects` list referencing the affected components by `bom-ref`/purl — producing a single VEX-style document for downstream tooling (Dependency-Track, etc.). Requires network access, so it conflicts with `--offline`. The standalone `vulns` report is unchanged.
* Added a --colour alias for --color
### Changed
* Improved licence report spacing between dependency groups and final log messages
* List the names of skipped non-Hex packages in the audit summary

## v0.1.0 - 2026-06-01
### Added
* Initial release of `licence_audit`, a CLI for auditing the licences of locked Hex dependencies in Gleam projects. Running `licence_audit` prints an inventory of the full resolved dependency tree from `manifest.toml`, including each package's locked version and declared licences fetched from Hex. Non-Hex dependencies (git, path, etc.) appear in the tree but their licences are not evaluated; they are counted in the `Skipped non-Hex packages` summary, matching the conservative behaviour of `cargo audit` / `cargo deny`.
* `licence_audit check` enforces a licence allow/deny policy and exits non-zero on violations, suitable for CI. Policy lives in `gleam.toml` under `[tools.licence_audit]` and can be overridden per-invocation with `--allow` / `--deny`:

```toml
[tools.licence_audit]
allow = ["Apache-2.0", "MIT"]
deny = ["GPL-3.0-only"]
```
* Report output is rendered as a dependency tree. Transitive packages appear indented under the dep that brought them in, using `├─`/`└─` connectors. A `Kind` column tags each package as `D` (direct dependency from `manifest.toml`'s `[requirements]`) or `T` (transitive). When `check` flags a transitive package, a `via: a → b → c` line is printed under the row showing the shortest dependency chain from a direct dep to the offending package.
* Interactive licence picker (`licence_audit update`) with tri-state selection: every discovered licence can be set to **Allow** (`+`), **Deny** (`-`), or **Ignore** (` `). Ignored licences are omitted from the written policy. Hotkeys: `space` cycles, `a`/`d`/`i` bulk-set.
* Requires Erlang/OTP 28.x or newer. Earlier OTP releases do not reattach stdin in raw mode, which prevents `licence_audit update` from receiving keyboard input.
* New `sbom` subcommand generates a CycloneDX 1.6 JSON Software Bill of Materials from `manifest.toml`. Supports `--output` to write to a file and `--offline` to skip Hex metadata fetch. Hex and GitHub git dependencies are supported; path and non-GitHub git deps cause a clear error. Components and `dependsOn` lists are emitted in a stable sorted order.
* Release workflow now generates a CycloneDX SBOM for each release and attaches it as `licence_audit-<version>.cdx.json`. Both the release archives and the SBOM are signed via GitHub Artifact Attestations (Sigstore-backed), verifiable with `gh attestation verify <file> --repo tylerbutler/licence_audit`.
* New `licence_audit vulns` subcommand that queries OSV.dev for known vulnerabilities affecting locked Hex and GitHub git dependencies. The report lists each affected package with its advisory IDs (GHSA / CVE / OSV), a severity bucket, and a one-line summary. Descriptive only — exits non-zero only on I/O, manifest, or network errors.
* `licence_audit check` now accepts `--vulns` to fold OSV.dev vulnerability checking into the policy gate, and `--vuln-severity` (or the `vuln_severity` config key) to set the failure threshold (`low`, `medium`, `high`, or `critical`; default `high`). The combined `check` exits non-zero when any advisory meets or exceeds the threshold, in addition to existing licence-policy failures.
* `sbom --reproducible` flag for deterministic output: the `serialNumber` is derived from a SHA-256 hash of the BOM content and the `timestamp` comes from `SOURCE_DATE_EPOCH` (default `1970-01-01T00:00:00Z`), so the same dependency set always renders byte-identical output.
* SBOM components include richer integrity and supplier metadata:

- A CycloneDX `publisher` field, populated best-effort from Hex `owners` (preferred) or `meta.maintainers` (fallback), joined alphabetically and comma-separated when there are multiple.
- A CycloneDX `supplier` object (`{name: "Hex", url: ["https://hex.pm/packages/<name>"]}`) is emitted for every Hex component so that "where the artefact came from" stays distinct from "who authored it".
- When a lockfile records `inner_checksum` alongside `outer_checksum`, the inner hash is surfaced as a `licence_audit:hex_inner_checksum` property. Gleam's current `manifest.toml` only records `outer_checksum`, so this is opt-in based on lockfile contents.
* `gen-docs` subcommand for auto-generating Markdown reference documentation from the CLI, powered by `glint_markdown`. Single- and multi-file modes, sentinel-comment injection into `README.md`, and a `--check` mode for CI drift detection. New `just docs` / `just docs-check` recipes; `docs-check` is wired into the CI workflow.
### Fixed
* Constrained the `etch` dependency to `>= 1.3.3 and < 1.4.0`. `etch` 1.4.0 removed the `etch/event.read` API, which breaks the build, so it is now excluded.
