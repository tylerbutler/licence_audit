# Re-enable update subcommand design

## Context

`licence_audit` already contains the `update` workflow in `src/licence_audit/update.gleam`, the parser builder in `src/licence_audit/cli.gleam`, and the runtime path in `src/licence_audit.gleam`. The subcommand is currently hidden by a feature flag in the CLI app builder.

## Goal

Restore `licence_audit update` as a supported CLI subcommand. It should be visible in help, parse into `cli.UpdateConfig`, and keep using the existing update implementation that discovers locked package licences, prompts for allow/deny selections, and writes `[tools.licence_audit]` policy to the configured TOML file.

## Approach

Remove the disabled 1.0-release gate by registering `update_command()` unconditionally alongside `check`, `sbom`, and `vulns`. Keep the existing `UpdateOptions` shape and runtime execution path unchanged so behavior stays limited to restoring access to the command.

Update CLI tests to cover the restored user-visible contract:

- `update` parses successfully with default options.
- `update` preserves relevant flags such as `--config`, `--manifest`, cache, verbosity, and color.
- Root help lists the `update` subcommand.

Update README usage documentation with a short `update` section explaining that it interactively reviews discovered licences and writes policy configuration.

## Error handling

Parser errors should continue to come from glint and existing option validation. Runtime errors remain handled by the existing `update.gleam` workflow: manifest errors, metadata fetch failures, picker cancellation, TOML editing failures, and file write failures return the current exit codes and messages.

## Validation

Run the targeted Gleam test suite after implementation. If the parser tests expose broader compile or formatting issues, address only issues directly related to restoring the update subcommand.
