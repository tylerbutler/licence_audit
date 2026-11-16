# Default licence report decision

Date: 2026-11-16

Status: Accepted

## Context

Bare `licence_audit` runs the non-enforcing licence report. The optional
`licence_audit report` command uses the same options and behavior.
Issue [#277](https://github.com/tylerbutler/licence_audit/issues/277) proposed
replacing the default scan with root help so that bare invocation would work
outside a project without reading project files.

## Decision

Keep the licence report as the default action and preserve root scan flags.
Keep `report` as an optional explicit form. Use `check` when findings must
fail a gate; report findings remain non-enforcing.

The default action gives users direct access to the tool's licence report.
The named form supports explicit scripts and workflows without requiring a
different entry point for existing users.

This decision supersedes the help-only root proposal in #277.

## Consequences

Outside a project, bare invocation can fail because required project inputs
are missing. This is expected scan behavior. Use `--help` or `-h` to discover
commands without project files.

For reviews and future PRs, treat default scanning and its missing-project
errors as intentional UX, not defects. Preserve root scan flags and the
equivalence of the default and named reports.

## Reconsider when

Changing the root to help-only behavior requires a new maintainer decision.
Do not reopen the proposal as a routine UX fix.
