# Developing `glint_markdown`

This document is for contributors. End-user docs live in [README.md](./README.md).

## Toolchain

This repository uses [mise](https://mise.jdx.dev/) to pin Gleam, Erlang,
`just`, and `changie`. Trust the local tool configuration once:

```sh
mise trust
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
just ci             # full validation (format-check + glint + check + test + test-js + build-strict)
just clean          # remove build artifacts
```

Run `just` with no arguments to see the full recipe list.

To run a single Gleam test module, invoke `gleam test` directly through mise
and pass the module name:

```sh
mise exec -- gleam test --target erlang -- glint_markdown_test
```

## Changelog

Every PR with user-visible changes should include a changie fragment:

```sh
just change                # interactive: pick a kind + write the body
just changelog-preview     # see what the next release will look like
```

## Releasing

Releases are driven by [changie](https://changie.dev/) + GitHub Actions:

1. Merge PRs with changelog fragments under `.changes/unreleased/`.
2. On `main`, `.github/workflows/release.yml` opens or updates a release PR
   (`release: vX.Y.Z`) that batches the fragments into `CHANGELOG.md` and
   bumps `gleam.toml`.
3. Merging the release PR triggers `.github/workflows/auto-tag.yml`, which
   creates the `vX.Y.Z` tag and GitHub Release.
4. The tag push triggers `.github/workflows/publish.yml`, which re-runs CI
   then `gleam publish --yes` to Hex (requires the `HEXPM_API_KEY` repo
   secret — generate one via `mise exec -- gleam hex authenticate` and
   add it under **Settings → Secrets and variables → Actions**).

## Upstream `glint` dependency

`gleam.toml` pins `glint` to a git ref on `tylerbutler/glint` because the
`glint.document/1` introspection API isn't on Hex yet. Once it lands
upstream (TanklesXL/glint) and is released, switch back to a Hex version
range:

```toml
glint = ">= X.Y.0 and < (X+1).0.0"
```
