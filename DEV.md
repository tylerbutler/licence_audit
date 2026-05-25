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

## Build from source

```sh
just build
```

`just build` compiles the Gleam project and produces the escript at
`./licence_audit`.

## Common tasks

```sh
just test           # gleam test
just check          # gleam check (type check only)
just format         # gleam format src test
just format-check   # gleam format --check src test
just ci             # full validation (format-check + check + test + strict build)
just clean          # remove build artifacts
```

Run `just` with no arguments to see the full recipe list.

To run a single Gleam test module, invoke `gleam test` directly through
mise and pass the module name:

```sh
mise exec -- gleam test --target erlang -- <module_name>_test
```

## Feature flags

The `update` subcommand is disabled for the 1.0 release via a compile-time
flag (`update_command_enabled` in `src/licence_audit.gleam`). The
implementation stays in the tree so the feature can be re-enabled post-1.0.
As a result:

- The shipped 1.0 CLI does **not** expose `licence_audit update`.
- The update implementation now depends on the `tomlet` Git dependency instead
  of a native helper binary.

## Library entry points

`run_with` and `run_with_progress` in `src/licence_audit.gleam` append
`--no-cache` so library and test runs never touch the on-disk DETS cache.
Only the CLI path uses the cache.

## Changelog

Changelog fragments are managed with
[changie](https://github.com/miniscruff/changie):

```sh
just change             # create a new changelog fragment
just changelog-preview  # preview the unreleased section
just changelog          # merge unreleased fragments into CHANGELOG.md
```

Releases are produced by the `release.yml` and `publish.yml` GitHub Actions
workflows; do not edit `CHANGELOG.md` or bump the version in `gleam.toml` by
hand.

For now, releases are escript-only GitHub release packages. The project is not
set up to publish the Gleam package to Hex.
