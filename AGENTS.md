# Copilot instructions for `licence_audit`

## Build, test, and lint commands

- Use `just` recipes for normal development; each recipe already runs via `mise exec --` with the pinned toolchain.
- Install deps: `just deps`
- Build CLI escript: `just build` (outputs `./licence_audit`)
- Strict CI-style build: `just build-strict`
- Type-check: `just check`
- Run full tests: `just test`
- Format: `just format`
- Format check: `just format-check`
- Lint: `just glint` (glinter; configured under `[tools.glinter]` in `gleam.toml`, fails only on error-level rules). `just lint` runs format-check + glint.
- Full local CI pass: `just ci`
- Run a single test module: `mise exec -- gleam test --target erlang -- <module_name>_test`
- Validate the generated SBOM: `just sbom-validate` runs three validators — `cyclonedx-cli`, `sbom-utility`, and cdxgen's `cdx-validate` (runs in CI). `just sbom-score` adds local-only quality scores from `sbom-tools` (CycloneDX 1.6-aware) and `sbomqs`; `just sbom-check` runs both. SBOM tooling is pinned in `.mise.toml` via the `github:` backend (cdxgen ships ~10 binaries, so its entry uses per-platform `asset_pattern` to select `cdx-validate`).

## High-level architecture

- **CLI parsing and action dispatch** is split between `src/licence_audit/cli.gleam` (glint command definitions -> `CliAction`) and `src/licence_audit.gleam` (top-level orchestration in `main`, `run_with_reporter`, and per-action handlers).
- **Audit/check pipeline** (`run_options_with_clients` in `src/licence_audit.gleam`) is:
  1. load+merge policy/config (`config.gleam`, `policy.gleam`)
  2. parse lockfile (`manifest.gleam`)
  3. resolve dependency paths for tree rendering (`manifest.dep_paths`)
  4. fetch Hex metadata (wrapped by `cache.gleam`)
  5. evaluate policy per package + render report tree (`report.gleam`)
  6. optionally run OSV vulnerability gate for `check --vulns` (`osv.gleam`)
- **Subcommand-specific flows**:
  - `update`: `src/licence_audit/update.gleam` discovers licenses and writes `[tools.licence_audit]` via `toml_port.gleam` (`tomlet`-based, comment-preserving edits).
  - `sbom`: `src/licence_audit/sbom.gleam` + `sbom_json.gleam` generate CycloneDX JSON and enforce supported purl sources.
  - `vulns`: `src/licence_audit.gleam` + `osv.gleam` query OSV batch + per-advisory details and render a separate vulnerability report.
- **HTTP clients** for Hex and OSV (`hex.gleam`, `osv.gleam`) follow the same pattern: open TLS connection per call, `await_up`, send request, decode response, close connection.

## Key repository conventions

- Library entry points (`run_with`, `run_with_clients`, `run_with_progress`) append `--no-cache`; on-disk cache behavior is intended for CLI runs, not embedded/library calls.
- `manifest.gleam` keeps non-Hex dependencies in graph data for tree/path context, but license auditing only applies to Hex packages.
- Unsupported sources are handled differently by command:
  - `sbom` fails for unsupported dependency sources (to avoid invalid purls).
  - `vulns` skips unsupported sources and reports the skipped package names.
- Cache failures are non-fatal by design (`cache.gleam`): audits continue, and warnings are deferred/surfaced via progress reporting.
- Progress/log output is managed through `progress.gleam`; user report output is printed first, then deferred progress events are flushed.
- Error mapping and exit semantics are centralized in `error.gleam` (`0` success, `1` enforced gate/usage failure, `2` input/config/network/decode/runtime error classes).
- PR workflow expects changelog fragments for relevant changes (`just change`) and Conventional Commit-style PR titles (validated in `.github/workflows/pr.yml` / `.commitlintrc.json`).
