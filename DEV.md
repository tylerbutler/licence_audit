# Developing `licence_audit`

This document is for contributors. End-user docs live in [README.md](./README.md).

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

## Reference coding

Use [XERJ](https://xerj.org/llms.txt) to search this project's sources and peer
implementations before writing code:

```sh
just xerj-install
just xerj-serve
```

Keep the node in that terminal. In a second terminal:

```sh
just xerj-index --dry-run
just xerj-index
just xerj-reference-add
just xerj-reference-index
just xerj-search "run_options_with_clients"
just xerj-reference "OSV querybatch"
```

Search local code first, then use a narrow query for the mechanism you need.
Read the source context and tests at each returned `file:line`. Check the
licence before adapting code and cite the reference you used. If the search
returns no useful result, state that and use normal source search.

The local search recipe needs `curl` and `jq`. XERJ indexes Gleam as plain-text
chunks without syntax-aware definitions; the recipe searches `text` as well
as the `body` and `defs` fields used for supported languages. Do not rely on
`xerj def` for Gleam symbols. A `?-?` line range means XERJ did not return line
metadata for that hit; read the file before citing a line.

`.mcp.json` registers `just _xerj mcp` for project-scoped MCP clients. Run the
client from this repository and reload its MCP configuration after setup.
The recipe supplies the endpoint, corpus home, and API key at runtime.

| Repository | Use |
|---|---|
| `EmbarkStudios/cargo-deny` | SPDX expressions, licence allow/deny policy, exceptions |
| `google/osv-scanner` | OSV batch queries, advisory handling, vulnerability gates |
| `oss-review-toolkit/ort` | Gleam analysis, CycloneDX SBOMs, third-party notices |
| `gleam-lang/gleam` | Gleam manifests, locked dependencies, dependency resolution |

The recipes store clones, commit and licence metadata, journals, and indexes
under `~/.local/share/xerj/licence-audit/`, outside the project tree.
`.xerjignore` limits the project index to `src/`, `test/` without fixtures, and
`native/`. `reference-code.xerjignore` limits the reference corpus to source
files and licence files. Do not build or edit the reference clones.

Re-run `just xerj-index` after source changes. `--no-graph` lets XERJ reconcile
added, changed, and deleted files. `just xerj-reference-add` keeps existing
clones at their current commits. To update a reference, use `git pull
--ff-only` in that clone, then run `just xerj-reference-add` to record its new
commit and `just xerj-reference-index` to refresh the index. For a replacement
index, use `just xerj-reference-index --fresh`; XERJ verifies it before
switching readers. The generated `corpora/licence-audit-references/corpus.json`
records full commit SHAs and licences for pinned rebuilds.

The node binds to loopback at `http://127.0.0.1:19200`, with the native API on
19201 and gRPC on 19202. It requires an API key stored in `data/admin.key`;
the recipes read that file without putting the key in project configuration.
The node uses local lexical embeddings, not neural embeddings. The config
disables external reranking and WAL forwarding.

On the Linux workstation used for this setup, the enabled user service
`xerj-licence-audit.service` runs the node without an open terminal:

```sh
systemctl --user status xerj-licence-audit --no-pager
systemctl --user restart xerj-licence-audit
systemctl --user stop xerj-licence-audit
```

On that workstation, `data/` links to
`/x23/tylerbu-xerj/licence-audit/data/`, because the home filesystem exceeds
XERJ's default 95% disk watermark. The node retains that disk safeguard.

Do not run `just xerj-serve` while that service is active. On another machine,
use the foreground recipe or create a user service that runs it. XERJ search
is a local development tool; `just ci` does not start or query it.

Indexing exit code `3` means completion with skipped files, not a total
failure. Read the `xerj-done` summary and skipped-file reasons before using
the corpus. Exit code `4` asks for a decision; do not bypass that gate.

## Build from source

```sh
just build
```

`just build` uses `gleam export escript` to compile production sources and
produce the escript at `./licence_audit`. The pinned compiler provides this
exporter, so the build does not need `gleescript`.
The build also copies the SQLite native application to `./sqlite_native/`.
Keep that directory beside the escript when you move or distribute it.

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

To test Unicode cache paths without network access:

```sh
just test-env-cache-paths
```

The test starts fresh Erlang VMs with `é` and `中` in `XDG_CACHE_HOME`
and `HOME`. It writes cache entries at the expected paths, then runs the
cache-enabled CLI and checks for cache hits. It also checks conversion
failures and the deferred warning when neither environment variable is set.

## SQLite cache spike

`spikes/sqlite_cache/` contains an isolated experiment with `sqlight` 1.2.0,
`esqlite` 0.9.0, and its bundled SQLite 3.50.4. The production integration uses
`esqlite` 0.10.0 directly through `cache_dir_ffi`, which preserves the UTF-8 and busy
handling without the `sqlight` wrapper. Each operation opens and closes its
own connection, so no transaction or connection remains open during a fetch.
Metadata and its optional timestamp share one atomic upsert. Immutable
metadata and notice values use a null timestamp.

`esqlite` 0.10.0 synchronously finalizes the private statement owned by `q/3`,
including on failure. The adapter maps the driver's remaining `'$busy'`
exception to a cache error. Do not use garbage collection or worker exit as a
statement-finalization barrier: resource cleanup can finish after those return.
The connection-lifetime test checks that WAL and SHM files are gone before an
operation returns.

**Upstream follow-up: [#168](https://github.com/tylerbutler/licence_audit/issues/168).**
The published driver can close a freed SQLite handle twice when opening fails.
AddressSanitizer reproduced a VM abort. This cannot be caught in Erlang.
The fix belongs upstream; adopt its published dependency when available so
normal Gleam source installs and packaged releases use the same native code.
This follow-up does not stop implementation or platform qualification.

`just test-cache-runtime` checks missing and unloadable native libraries in
fresh VMs and verifies that disabled caches do not load the NIF.

Keep standalone Gleam experiments outside `src/`, `test/`, and `dev/`.
Gleam scans nested projects in those source directories, including their
downloaded dependencies. Trellis excludes `spikes/**` from release work.

```sh
just spike-sqlite           # Fresh Erlang VMs
just spike-sqlite-escript   # Exported escript with an esqlite sidecar
just spike-sqlite-native    # Linux x86_64 glibc, Debian 12 and Ubuntu 24.04
```

The native recipe needs Docker, Rust, and cargo-zigbuild. It selects Zig
0.14.1 with mise and downloads the release Erlang runtime into a
spike-local cache. This avoids reusing a host ERTS cached by an earlier
`--erts` build. Neither test container has system Erlang.

The shared shell check covers persistence across VMs, an atomic
value/timestamp upsert, parameter binding, Unicode values, and Unicode
paths with spaces. A second VM holds a write transaction while other VMs
read the committed value and skip busy writes. The check requires three
busy writes to finish in less than 1000 ms of database-call time in total.
It terminates writers with SIGTERM and SIGKILL, checks recovery of a committed
WAL entry and rollback of uncommitted data, and verifies that a corrupt
database produces an error without replacing the file.
Each check uses a temporary HOME and cache.

`just spike-sqlite` also runs Erlang EUnit checks for the filename byte limit,
prepare/bind/step errors, and busy reads, writes, and WAL setup. It checks
read-only connections, database-full errors forced with a page limit, and
preservation of a real DETS file. These checks reuse connections after
errors and lock release to check statement cleanup. A snapshot check
compares copies made before and after the last connection closes.

You can run the same check against another executable:

```sh
just spike-sqlite-binary /absolute/path/to/sqlite_cache_spike
```

### Findings

The BEAM and sidecar-backed escript checks pass on Linux x86_64. The native
glibc checks pass on Debian 12 and Ubuntu 24.04 with the downloaded release
ERTS. The spike adds a small Erlang adapter for two driver failures:

- **Unicode paths need UTF-8 bytes.** The native open function copies
  filenames with `ERL_NIF_LATIN1`. The adapter passes the UTF-8 bytes as list
  elements instead of Unicode code points. The shell check uses Greek,
  accented Latin, and emoji characters and checks the actual database path.
- **Busy queries need explicit result handling.** `esqlite3:fetchall1` does
  not handle `'$busy'`. The adapter uses `prepare`, `bind`, `step`, and `reset`
  to return a `sqlight.Busy` error and release statement locks. It preserves
  errors from preparation, binding, and execution, and checks reset errors.
  The upsert now uses a single atomic statement without the `BEGIN IMMEDIATE`
  workaround. The spike sets `busy_timeout=0` before WAL setup.

Use the spike's open/query adapter rather than `sqlight.open` or
`sqlight.query` when building on this experiment.

### Packaging failures found by the spike

These findings apply to the isolated spike, not the production adapter.
Production discovers its adjacent `sqlite_native/esqlite` application before
loading the NIF and returns load failures as deferred cache warnings. Native
release builds must compile the NIF for each target platform; cross-building
the Queso launcher alone is not sufficient.

- **The release build does not build target-specific SQLite NIFs.** Queso
  copies the host-built NIF into its shipment. The x86_64 musl executable
  builds, but fails in Alpine at `esqlite3_nif.open/1` with `undef`. Its
  shipment contains the same x86_64, glibc-linked `esqlite3_nif.so` as the
  host build. The production publish job builds all seven declared targets
  on one Ubuntu runner. Target-native or cross-compiled NIFs still need
  packaging checks; ARM, macOS, and Windows execution remain unverified.
- **The escript does not find its sidecar without `ERL_LIBS`.** The escript
  recipe copies `esqlite`'s `ebin/` and `priv/` directories beside the escript
  and sets `ERL_LIBS` to that bundle's `lib/` directory. With that variable
  unset, both a bare escript and an escript with an adjacent sidecar fail
  from an unrelated working directory. Production installation must not
  depend on the caller setting this variable.
- **A missing or unloadable NIF crashes instead of disabling the cache.**
  The adapter's open call raises `undef` before it can return a
  `sqlight.Error`. This violates the production cache's nonfatal-failure
  contract. The current escript and musl failures both exercise this path.

### Compatibility and cache snapshots

The tested Linux build accepts an absolute database path of **504 UTF-8
bytes**, including directories, and supports WAL writes at that length.
Paths of 505 through 511 bytes return `Cantopen`. SQLite's Unix VFS limit
is 512 bytes and its pager reserves eight bytes for a journal suffix.
At 512 input bytes, the NIF rejects the filename before SQLite opens it.
These failures return structured errors; the adapter also rejects NUL
bytes. Production retains this documented SQLite limit and warns without
failing the audit. Use a shorter cache path instead of changing the native
dependency.

A copy of the live database file alone omits committed WAL data. The
snapshot check cannot read the new table from that copy. After the last
connection closes, the same copy includes the committed row. CI should
save caches after commands finish and close their connections. A snapshot
of an active cache needs SQLite's backup mechanism or coordinated access;
copying the directory during writes does not guarantee a consistent snapshot.

The earlier Debian 12 failure came from bundling the local ERTS, which
requires `GLIBC_2.38`. The downloaded release ERTS passes there. The locally
compiled SQLite NIF requires glibc 2.34; this does not establish support for
older glibc systems or for NIFs compiled on another release runner.

The spike implements no TTL policy, stale-data fallback, DETS migration,
or production CLI integration.

Reference mechanisms: `src/licence_audit/cache_dir.gleam:115` for best-effort
cache access, `src/licence_audit/args_ffi.erl:4` for CLI argument conversion,
and `test/licence_audit/cache_process_test_ffi.erl:4` for monotonic timing.
Driver details are in
[`lpil/sqlight/src/sqlight_ffi.erl:7`](https://github.com/lpil/sqlight/blob/v1.2.0/src/sqlight_ffi.erl#L7-L12),
[`mmzeeman/esqlite/src/esqlite3.erl:220`](https://github.com/mmzeeman/esqlite/blob/master/src/esqlite3.erl#L220-L228),
and
[`mmzeeman/esqlite/c_src/esqlite3_nif.c:190`](https://github.com/mmzeeman/esqlite/blob/master/c_src/esqlite3_nif.c#L190-L192).
The spike adapters are in `spikes/sqlite_cache/src/sqlite_cache_spike_ffi.erl:4`
and `spikes/sqlite_cache/src/sqlite_cache_spike.gleam:165`. Both driver
packages use Apache-2.0. For statement cleanup semantics, see
[`sqlite3_reset`](https://www.sqlite.org/c3ref/reset.html): a reset error can
report the preceding step's failure, even though SQLite has reset the statement.
The path checks are in
`spikes/sqlite_cache/test/sqlite_cache_spike_ffi_tests.erl:39`; storage failure
and snapshot checks follow in the same module. Release packaging starts at
`.github/workflows/publish.yml:23`, and `gleam.toml:50` lists its targets.
For snapshot requirements, see [SQLite's WAL documentation](https://www.sqlite.org/wal.html)
and [online backup API](https://www.sqlite.org/backup.html).

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
caches. Concurrent CLI runs can share cached entries. `--no-cache` bypasses
the caches, and `--cache-path=PATH` overrides the licence metadata cache
location. Source-built escripts require the `sqlite_native/` directory beside
the executable for cache access; `just build` copies it there.

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
non-expiring cache entries. Hex publisher data is omitted because package
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

When a same-repository `release/pending` PR is merged, `auto-tag.yml` checks
out its merge commit and runs `trellis tag create --github-release`. This
uses the tag format in `gleam.toml` and the matching changelog section.
It does not require a PR label or Changie configuration. The GitHub App
token lets the tag push start `publish.yml`.

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
