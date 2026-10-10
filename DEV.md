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

`just build` compiles the Gleam project and produces the escript at
`./licence_audit`.

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

## Common tasks

```sh
just test           # gleam test
just check          # gleam check (type check only)
just format         # gleam format src test
just format-check   # gleam format --check src test
just glint          # gleam run -m glinter (linter; fails only on error-level rules)
just lint           # format-check + glint
just ci             # full validation (format-check + glint + check + test + runtime startup + strict build + docs-check + sbom-drift-check + sbom-validate)
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
DETS caches. The CLI uses the cache by default; `--no-cache` bypasses it, and
`--cache-path` overrides the licence metadata cache file.

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

Releases include the existing escript artifacts plus self-contained Queso
archives for Linux (glibc and musl), macOS, and Windows x86_64 targets. Linux
static targets are excluded because Queso static binaries do not export the NIF
symbols (crypto/SSL) that this CLI requires — use glibc or musl archives on
Linux instead. The `aarch64-windows` target is deferred because Queso requires
an explicit Windows ARM64 ERTS and there is no trustworthy pinned prebuilt OTP 28
archive for that target.
