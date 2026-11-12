# Developing `licence_audit`

This document is for contributors. The [website](https://licence-audit.tylerbutler.com/docs)
is the canonical user documentation.

## Toolchain

This repository uses [mise](https://mise.jdx.dev/) to pin Gleam and Erlang
versions. Trust the local tool configuration once:

```sh
mise trust
```

You normally do not need to run `mise exec --` directly — every `just`
recipe wraps its commands in `mise exec --` already, so `just build`,
`just test`, etc. pick up the pinned toolchain automatically. Only fall
back to `mise exec -- <command>` when running tools that don't have a
`just` recipe.

The stable compiler and just versions are exact pins in `.mise.toml`.
`mise.lock` records versions and backend-provided download URLs and SHA-256
hashes for Linux and macOS on x86-64 and ARM64. Rebar3 uses the explicit GitHub
release backend so its lock entries include URLs and hashes. Install without
changing the lockfile:

```sh
mise install --locked
```

The Erlang Linux build target is fixed to Ubuntu 24.04 so locked installs use
the same OTP asset when the hosted runner's Ubuntu version changes.

If you have unrelated global mise tools without their own lockfile, select
the project tools explicitly (for example, `mise install --locked erlang
gleam just github:erlang/rebar3`). A bare install includes global tools as well.

CI requires a locked install. For a tool update, change its pin, regenerate
the lockfile, and review the versions, URLs, and hashes before committing:

```sh
mise lock --platform linux-x64,linux-arm64,macos-x64,macos-arm64
just build-strict
just test
```

The lockfile pins the URLs and checksums of mise-installed tools, including
Queso and cargo-about. The release job also installs the Rust targets, Zig,
cargo-zigbuild, and system packages. These use their own trust and verification
mechanisms. The build is not fully hermetic.

## Build from source

```sh
just build
```

`just build` uses `gleam export escript` to compile production sources and
produce the escript at `./licence_audit`. The pinned compiler provides this
exporter, so the build does not need `gleescript`.
The escript has no native dependencies. You can move it without other files.

### Vendored packages

The repository tracks `glint` and `glint_markdown` with
[git-subrepo](https://github.com/ingydotnet/git-subrepo):

| Upstream snapshot | Compiled sources |
|---|---|
| `vendor/glint/` | `src/licence_audit/internal/vendor/glint.gleam` and `glint/` |
| `vendor/glint_markdown/` | `dev/licence_audit/internal/vendor/glint_markdown.gleam` and `glint_markdown/` |

Normal builds use the committed source copies. You need git-subrepo only to
pull upstream changes or push patches. Do not edit the generated copies.
Make upstream patches in `vendor/`, then run `just vendor-sync`.

To update a snapshot, start with a clean worktree:

```sh
git subrepo pull vendor/glint -m "chore(deps): update vendored glint"
git subrepo pull vendor/glint_markdown -m "chore(deps): update vendored glint_markdown"
just vendor-sync
just vendor-check vendor-test test-vendor-production
```

Each pull creates an import commit. Review and commit the regenerated copies
after the pull. The `.gitrepo` files record the upstream repositories and
commits.

`scripts/vendor_sync.py` copies source files, rewrites vendored imports and
Erlang FFI names, formats Gleam sources, and writes the root `NOTICE`.
It excludes upstream tests, examples, and package configuration. If an update
adds dependencies, declare their Hex requirements in the root `gleam.toml`.
The script rejects unreviewed licence changes and unsupported source files.
Run these recipes with Python 3.11 or later.

`dev/licence_audit/gen_docs.gleam` uses the development-only Markdown generator.
`just docs` updates the `cli-reference` marker regions in
`website/src/pages/docs/index.md` and each command guide. It derives usage,
flags, types, defaults, and descriptions from `glint.document(cli.app())`.
Edit surrounding guide prose directly; do not edit generated regions.
`just docs-check` compares generated content without writing. Missing or
malformed marker pairs are errors. The README and `docs/` command stubs link
to the website and are not generator outputs.
`just test-docs` tests read-only drift detection, regeneration, and missing
pages/markers in isolated guide copies.

Run `just website-deps website-check website-build` to install locked website
dependencies, check Astro types and worker tests, and build the static site.
These recipes use the Node and pnpm versions in `.mise.toml`; they do not deploy.
`just ci` includes website validation.

Production builds and Hex packages exclude `dev/` and its `glugify` dependency.
Gleam compiles native files from `dev/` in production, so the sync script
replaces the Markdown generator's exit shims with core-library calls. It
keeps the reviewed Erlang filesystem helper under `native/dev/`, outside
the compiler's source roots. The docs recipes compile that helper into the
development build only. Its JavaScript companion stays in `dev/`.
The script rejects new or changed native development files until a
contributor reviews them.
`just test-vendor-production` checks the production application, BEAM files,
and shipped escript.
The root `NOTICE` records both vendored packages and includes their Apache-2.0
licence text. Release archives include this notice.

To build self-contained native executables with Queso, install Queso's
package-time dependencies for your target and run:

```sh
just build-queso
```

Queso writes executables to `build/queso/`. The full multi-target build is
opt-in for local development. PR CI builds and tests only Linux x86_64 glibc.

### Native HTTP smoke test

On Linux x86_64, build the glibc executable and test it without system Erlang:

```sh
mise exec -- queso build --target x86_64-linux-glibc
just smoke-native-http build/queso/licence_audit-<version>-x86_64-linux-glibc
```

Replace `<version>` with the version in `gleam.toml`. Queso 0.3.0 treats
glibc as a cross target even on a glibc host, so this build needs Rust,
Zig, and cargo-zigbuild. CI uses Zig 0.14.1 and cargo-zigbuild 0.23.4.

The smoke recipe needs Docker and network access. It runs the executable
in a Debian container with CA certificates but no Erlang installation.
A temporary one-package project, HOME, and cache keep the test separate
from local configuration. The test makes real Hex and OSV requests for a
licence report, a vulnerability report, and `check --vulns`. It also checks
help, version, and offline SBOM output. Network failures fail the test;
failure logs are printed before temporary files are removed.

PR CI runs this test on the built executable. Publishing runs the same test
on the extracted release archive before upload. Live requests are not part
of `just test` or `just ci`.

To test application startup and its error handling without network access:

```sh
just test-runtime-startup
```

This uses fresh Erlang VMs, because the Gleam test runner starts application
dependencies before it runs tests. The CLI must also start these dependencies
when Queso calls `main()` directly.

The same recipe checks error, throw, and exit exceptions at the CLI boundary,
including cleanup while the exception unwinds. `just test-cli-streams` checks
the escript with an invalid CA bundle path
(`ERL_FLAGS='-public_key cacerts_path [47,110,111]'`).
These runtime failures must exit 2 without a raw
stack trace. Policy and usage failures must still exit 1.

To test environment conversion and cache paths without network access:

```sh
just test-env-cache-paths
```

The test checks `é` and `中` in `XDG_CACHE_HOME` and `HOME` with caching
disabled. It then writes cache entries, runs the cache-enabled
CLI, and checks for cache hits. It also checks conversion failures and the
deferred warning when neither environment variable is set.

## File cache

`cache_dir.gleam` stores each cache entry as one JSON file in the cache
directory. The file name is the lowercase hex SHA-256 hash of the key, with a
`.json` suffix. The file contains the key, the optional timestamp, and the
value. A read that finds a different key, invalid JSON, or invalid UTF-8 gives
a deferred warning and a cache miss. Immutable metadata and notice values use
a null timestamp.

A write goes to a temporary file with a random name in the same directory.
Then `simplifile.rename` moves it over the entry file. On POSIX systems, this
rename is atomic, so a reader sees the old entry or the new entry. OTP's
Windows rename moves an existing entry aside before it moves the new file into
place. Thus a reader can see no entry for a short time, which is a cache miss.
Readers never see a partial file. If a rename fails and the entry file exists,
another writer won the race, and the write is a success.

The cache has no locks. Concurrent commands can share a cache directory: when
two writers race on one key, both values are valid. A failed write leaves a
`.tmp` file only if the command stops during the write. Lookups ignore these
files. The cache does not remove old entries; delete the directory to clear it.

### Cache snapshots

The cache directory is safe to copy at any time. A copy can omit entries that
a running command writes during the copy, but each copied entry is complete.

## Common tasks

```sh
just test           # gleam test
just check          # gleam check (type check only)
just format         # gleam format src test dev
just format-check   # gleam format --check src test dev
just glint          # gleam run -m glinter (linter; fails only on error-level rules)
just lint           # format-check + glint
just ci             # full validation (vendoring + formatting + lint + check + tests + builds + docs + SBOM)
just clean          # remove build artifacts
```

Run `just` with no arguments to see the full recipe list. The local `just ci`
recipe and GitHub Actions both validate the SBOM after checking the committed
SBOM for drift.

For PRs from `release/pending`, CI and PR Validation cancel older queued
and running workflow runs when a new run arrives. Each workflow has its own
concurrency group for the PR. Other branches and release builds use separate
groups for each run and do not cancel earlier runs.

To run a single Gleam test module, invoke `gleam test` directly through
mise and pass the module name:

```sh
mise exec -- gleam test --target erlang -- <module_name>_test
```

## Update subcommand

The shipped CLI exposes `licence_audit update`. It interactively reviews
discovered licences and writes the selected `[tools.licence_audit]` policy
using the `tomlet` Git dependency; no native helper binary is required.

## Library entry points

`run_configured(args, clients, reporter)` in `src/licence_audit.gleam` is the
consolidated injected runner for tests and library callers. Pass a `Clients`
bundle (use `default_clients()` and replace fields as needed) and a progress
reporter; it returns the run result and captured progress events. `run(args)`
is the result-only convenience entry point with default clients and progress
disabled. Both runners add `--no-cache`, so they do not touch the on-disk
caches. Concurrent CLI runs can share cache paths. `--no-cache` bypasses
the caches, and `--cache-path=DIR` overrides the licence metadata cache
directory.

## SBOM reproducibility (`sbom --reproducible`)

The `sbom` subcommand emits a fresh random `serialNumber` and a
wall-clock `metadata.timestamp` by default, and switches to a
content-derived `urn:uuid` (SHA-256 of the BOM payload, formatted as an
RFC 9562 v8 UUID) plus a `SOURCE_DATE_EPOCH`-driven timestamp under
`--reproducible`. Components and `dependsOn` lists are sorted
deterministically in both modes — that ordering is a prerequisite for
the content-derived serial and also keeps regular diffs of committed
SBOMs useful.

Reproducible mode does not use the mutable Hex package API. It reads component
metadata from each checksum-verified Hex `metadata.config` and from each Git
archive at the manifest commit. The immutable results use content-addressed,
non-expiring cache entries. For Git dependencies with a manifest `path`, metadata
comes from that package subdirectory's `gleam.toml`, not the repository root.
The cache key includes the package path. Hex publisher data is omitted because package
owners can change after publication. `--vulns` is incompatible with
`--reproducible` because OSV advisory data also changes over time.

The flag exists rather than being always-on for these reasons:

- **CycloneDX semantics.** The spec defines `serialNumber` as a unique
  identifier for *this BOM document instance* and `metadata.timestamp`
  as the actual creation time. Always-reproducible output collapses
  multiple generations of the same dependency set onto one serial and
  reports a fake timestamp, which can break downstream consumers
  (Dependency-Track, vuln scanners, in-toto/SLSA attestations) that
  treat the serial as per-build identity.
- **Most uses want per-build identity.** Uploading to an SBOM registry,
  attaching to a release, or feeding a scanner benefits from a fresh
  UUID and real timestamp; reproducibility primarily helps the
  commit-and-diff workflow.
- **Convention.** Reproducible-builds tooling is conventionally
  opt-in (flag or `SOURCE_DATE_EPOCH`) precisely because it trades away
  useful metadata.
- **Reversibility.** Going always-reproducible later would require a
  new flag like `--with-timestamp` to recover today's defaults, which
  is uglier than the current `--reproducible` opt-in.

Library callers select the mode via the `SerialNumber` variant on
`SbomInput` (`FixedSerial(String)` for the default random-v4 path and
`ContentDerivedSerial` for the reproducible path).

The release workflow (`.github/workflows/publish.yml`) intentionally
does **not** pass `--reproducible`. A release SBOM is a one-shot
artifact attached to a specific tag and signed by `actions/attest`, so it
must have a unique `serialNumber` and a real `metadata.timestamp` —
that is what downstream SBOM registries and vuln scanners expect, and the
Sigstore attestation already provides a verifiable creation time.
Reproducibility is for the "commit the SBOM and diff it in CI" workflow,
not for signed per-release artifacts.

## Changelog

Changelog fragments and versions are managed with
[Trellis](https://trellis.tylerbutler.com):

```sh
just change Fixed "Fix ..."                # create a changelog fragment
just changelog-preview                    # preview pending version changes
just changelog                            # apply versions and regenerate changelogs
just doctor                               # check workspace and release invariants
```

Releases are produced by the `release.yml` and `publish.yml` GitHub Actions
workflows; do not edit `CHANGELOG.md` or bump the version in `gleam.toml` by
hand.

To prepare `1.0.0-rc.0`, dispatch the release workflow on `main`:

```sh
gh workflow run release.yml --ref main -f pre=rc -f version=1.0.0
```

After the candidate PR merges, new or changed fragments and release-owned
source changes on `main` can open the next candidate PR. Trellis archives
candidate fragments in `.changes/licence_audit/v<prerelease>.toml` and removes
them from `unreleased`. Each later candidate includes only new changes.
To promote the candidate to `1.0.0`, dispatch:

```sh
gh workflow run release.yml --ref main -f pre=none
```

Promotion combines the target version's candidate archives with any remaining
fragments into the stable release notes. Keep the generated archives committed
with release files. After the promotion PR merges, pushes resume the normal
stable release flow. Use manual
dispatch to enter a candidate cycle or promote it. Leave both inputs empty to
prepare a normal stable release when `main` is stable. Empty inputs on a
candidate fail with a request to use `pre=none`; they do not promote it.

The `[tools.trellis.release]` defaults enable `resume`, `auto_pre`, and
`skip_unchanged`. Automatic pushes preserve an open release PR's original target
and mode, including a pending promotion. Without a pending PR, Trellis continues
the committed candidate label and skips unchanged release content. Its content
check includes pending fragments and release-owned `gleam.toml`, `src/`, and
`priv/` files. Unrelated docs and excluded examples do not trigger a candidate.
Closed PRs and leftover release branches do not supply pending intent.

Manual runs disable those defaults and replace the pending request with the
supplied inputs. Release preparation runs one job at a time. The workflow
appends Trellis's `--github-output` records to `$GITHUB_OUTPUT` and refreshes
the SBOM and notices only for `outcome=prepared`. `unchanged` and `no_changes`
skip that work; invalid release state and other errors fail the job.

Trellis 1.5.0 retries delayed GitHub head metadata after a successful branch
push. If the previous head persists, preparation fails without updating the
PR description or emitting success records. Concurrent head changes and
closed, merged, or retargeted PRs still fail.

Preview candidate or promotion plans without GitHub writes:

```sh
just changelog-preview --pre rc --set licence_audit=1.0.0
just changelog-preview --pre none
```

`just release-pr` uses the same native defaults as automatic pushes. It pushes
`release/pending` and creates or updates its PR. To replace a request locally,
pass `--no-resume --no-auto-pre --no-skip-unchanged` and the desired `--pre` and
`--set` options. Direct `just changelog` applies versions to the local checkout;
it does not use release-PR continuation defaults.

### Release history and older PRs

Trellis 1.5.0 reads proposed versions and release inputs from Git history.
Full history is required; the release workflow uses `fetch-depth: 0`.
Older PRs do not need `.changes/release.toml` to resume. Preparation removes
that obsolete file from its next generated release commit.

The legacy migration for
[#239](https://github.com/tylerbutler/licence_audit/pull/239) is complete:
the PR merged and `1.0.0-rc.1` was published. Do not repeat its recovery.
Stale or ambiguous history still fails preparation. Check the current PR,
release mode, and target before using a manual replacement. A candidate
must remain in its version series; promote it before starting another series.

When a same-repository `release/pending` PR is merged, `auto-tag.yml` checks
out its merge commit and runs `trellis tag create --github-release`. This
uses the tag format in `gleam.toml` and the matching changelog section.
It does not require a PR label or Changie configuration. The GitHub App
token lets the tag push start `publish.yml`.
Trellis marks candidate GitHub Releases as prereleases. The `v*` tag trigger
publishes the same artifacts for candidates and stable releases.

### Hex publication

After CI, binary packaging, and GitHub Release asset upload succeed,
`publish.yml` publishes each new release to Hex, including `0.x`, RCs,
and other prerelease types. The tag must match `v{version}` from its
`gleam.toml`. The workflow checks out an exact tag and runs the pinned
`trellis publish --tag "$RELEASE_TAG"`.

Before the first publication, a Hex package owner must create an API
key with permission to publish `licence_audit` and store it as the repository
Actions secret `HEXPM_API_KEY` (Settings > Secrets and variables > Actions).
For the first publication, the key must permit package creation; after
creation, restrict it to this package. Do not put the key in source files
or workflow inputs. A missing key fails the Hex job before publication.

Trellis checks the tag/version match, skips versions already on Hex, and
retries Hex API, build, test, and publication failures. It runs Gleam
format, strict build, and test checks before publishing. Publication jobs
for the same tag run one at a time. Failed retries fail the job.

To recover a failed Hex publication, fix the secret or reported error and
rerun the failed Hex job. If the workflow needs a fix, merge it
to `main`, then dispatch from `main` with the existing tag:

```sh
gh workflow run publish.yml --ref main -f tag=v1.0.0-rc.0
```

The dispatch uses the tagged package and its pinned toolchain. It does not
backfill historical releases unless you dispatch their tags. Preview the
publication plan without credentials or publication:

```sh
mise exec -- trellis publish --tag v0.14.0 --dry-run
```

Use a tag that matches the checked-out package version. The dry run reads
the public Hex API. The Gleam exporter includes runtime native sources,
`LICENSE`, and vendored `NOTICE`; no custom file list is needed.

To recover a merged release that has no tag or GitHub Release, run the
auto-tag workflow manually against the current version on `main`:

```sh
gh workflow run auto-tag.yml --ref main
```

Trellis preserves existing exact tags and releases. This command does not
backfill older versions. If the tag exists but artifact publishing failed,
rerun the failed Publish job or dispatch `publish.yml` with that tag.

If you fix the Publish workflow, merge the fix to `main` and dispatch the
workflow from `main` with the existing tag:

```sh
gh workflow run publish.yml --ref main -f tag=v0.12.2
```

Replace `v0.12.2` with the tag to rebuild. Rerunning the original failed run
uses the old workflow, without the fix.

Releases include the existing escript artifacts plus self-contained Queso
archives for Linux (glibc and musl), macOS, and Windows x86_64 targets. Linux
static targets are excluded because Queso static binaries do not export the NIF
symbols (crypto/SSL) that this CLI requires — use glibc or musl archives on
Linux instead. The `aarch64-windows` target is deferred because Queso requires
an explicit Windows ARM64 ERTS and there is no trustworthy pinned prebuilt OTP 28
archive for that target.

### Release licence material

Publish includes the generated `THIRD_PARTY_NOTICES.txt`, project `LICENSE`,
and vendored `NOTICE` in each archive. It also embeds these documents under
`META-INF/licenses/` in the bare escript ZIP payload.

Run `just test-release-notices` to test staging and archive checks. Publish reads
the notice bytes from each staged tar/ZIP and the bare escript, and compares
them with the required source documents. Missing, empty, or changed documents
stop publication. Older tags without required documents also fail this check.

After building native executables, Publish runs
`mise exec -- python3 -B scripts/runtime_notices.py`. It uses a fresh,
worktree-local Queso cache under `build/release-cache/` so the collector reads
the runtime installations and launcher lockfile used by that build. For a
focused local check against an existing Queso cache, pass
`--target x86_64-linux-glibc --cache <cache-directory>/queso`.

The collector writes `build/release-notices/<target>/` with these inputs:

- The pinned OTP release's checksummed `bom.spdx.json`, its extracted licence
  terms and copyright statements, tagged source licence files, and SPDX texts.
  This inventory includes a superset of the OTP applications in the executable.
- The Queso launcher's actual `Cargo.lock`, checked against the pinned Queso
  source, and target-filtered `cargo-about --locked --fail` licence material.
  The comparison accepts CRLF line endings from Queso's Windows source archive;
  the bundle keeps the original bytes. Queso's
  [source packer](https://github.com/jtdowney/queso/blob/v0.3.0/src/pack.rs#L22-L27)
  preserves those bytes.
  The collector also preserves separate licence, NOTICE, and copyright files
  from the resolved crate sources, including bundled native code.
  `queso/source-packages.json` records immutable crate source URLs and their
  locked checksums, including source for dependencies under MPL-2.0.
- Rust's bundled `COPYRIGHT-library.html` and licence texts, plus Zig's bundled
  native-library notices, including compiler runtime and MinGW material. The
  collector records the toolchain versions.
  Rust's release manifest and the installed Zig wheel's PyPI metadata provide
  the matching distribution URLs and published checksums.
- The distribution's external OpenSSL licence and authors, using the version
  string from its actual `crypto` library. OTP's source SBOM can name a different
  OpenSSL version from the one linked into a platform distribution.
- Linux `versions.txt` and the exact Debian source packages' copyright files
  for statically linked OpenSSL, ncurses, and GCC runtimes. Alpine distributions
  use the corresponding upstream musl, ncurses, and GCC licence material.

`otp-distribution.json` records Queso's selected OTP asset URL and the checksum
published in GitHub release metadata. Publish requires the download URL and
hash in Queso's fresh build log to match that metadata; a local cache-only
collection records that it has no such download verification.
`manifest.json` records fetched source
URLs/checksums and checksums of the collected documents. Publish stages the
bundle as `runtime-notices/` and compares its archived bytes with that manifest.

Missing upstream material, unresolved licence expressions, checksum mismatches,
or an unidentifiable external OpenSSL version stop publication. The collector
preserves upstream attribution; it does not assert legal review or runtime
validation. Keep the licence files and source-location records when you
redistribute an archive.
