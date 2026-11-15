# Developing `glint_markdown`

This document is for contributors. End-user docs live in [README.md](./README.md).

## Toolchain

This repository uses [mise](https://mise.jdx.dev/) to pin Gleam, Erlang,
`just`, and [Trellis](https://trellis.tylerbutler.com). Trust the local tool
configuration and install the tools:

```sh
mise trust
mise install
```

You normally do not need to run `mise exec --` directly — every `just`
recipe wraps its commands in `mise exec --` already, so `just build`,
`just test`, etc. pick up the pinned toolchain automatically.

## Build

```sh
just build           # gleam build
just build-strict    # gleam build --warnings-as-errors (used in CI)
```

## Common tasks

```sh
just test           # gleam test (Erlang target)
just test-js        # gleam test --target javascript --runtime nodejs
just check          # gleam check (type check only)
just format         # gleam format src test
just format-check   # gleam format --check src test
just glint          # gleam run -m glinter (linter; fails only on error-level rules)
just lint           # format-check + glint
just doctor         # Trellis release configuration and fragment checks
just ci             # full validation (doctor + format-check + glint + check + test + test-js + build-strict)
just clean          # remove build artifacts
```

Run `just` with no arguments to see the full recipe list.

Both test recipes also run CLI subprocess checks. These check stdout and stderr,
exit codes, safe destinations, and links injected into nested READMEs.

To run a single Gleam test module, invoke `gleam test` directly through mise
and pass the module name:

```sh
mise exec -- gleam test --target erlang -- glint_markdown_test
```

## Changelog

Include a Trellis fragment for user-visible changes:

```sh
just change Fixed "Describe the change"
just changelog-preview     # preview the next version
```

Fragments are TOML files under `.changes/unreleased/` with `package`, `kind`,
and `body` fields. Use `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or
`Security` as the kind; Trellis also accepts its built-in kinds.

The PR changelog check considers changes to any file in this package. Missing
entries produce an advisory comment; invalid fragments fail the check.
Run `mise exec -- trellis changelog check --base origin/main` to check a branch.

## Releasing

This package uses Trellis's `git_only` lifecycle: version bumps, Git tags,
and GitHub Releases, without Hex publishing.

1. Merge PRs with changelog fragments under `.changes/unreleased/`.
2. On `main`, `.github/workflows/release.yml` runs `just release-pr` to open
   or update `release/pending`. The PR (`release: glint_markdown vX.Y.Z`)
   batches the fragments into `.changes/glint_markdown/`, rebuilds
   `CHANGELOG.md`, and bumps `gleam.toml`.
3. Merge the release PR. `.github/workflows/auto-tag.yml` checks out its
   merge commit and creates the immutable `vX.Y.Z` tag and GitHub Release
   with the matching changelog section as release notes.

The release-PR workflow needs the existing `RELEASE_APP_ID` and
`RELEASE_APP_PRIVATE_KEY` repository secrets. The GitHub App needs contents
and pull-request write access so its release PR triggers validation workflows.
Tagging uses the workflow's `GITHUB_TOKEN`; no Hex API key is required.

For local use, `just release-pr` requires a clean worktree and GitHub
authentication (`GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth login`). It regenerates
the remote `release/pending` branch, so do not edit that branch by hand.
`just changelog` applies the version bump and consumes the pending fragments;
use `just changelog-preview` for a read-only plan.

## Upstream `glint` dependency

`gleam.toml` pins `glint` to a git ref on `tylerbutler/glint` because the
`glint.document/1` introspection API isn't on Hex yet. Once it lands
upstream (TanklesXL/glint) and is released, switch back to a Hex version
range:

```toml
glint = ">= X.Y.0 and < (X+1).0.0"
```
