---
layout: ../../layouts/DocsLayout.astro
title: update
description: Select the discovered licences and write a policy to your Gleam configuration.
---

Use `update` to create or change a policy. It reads locked licence metadata
and writes your choices to `[tools.licence_audit]` in the selected TOML file.
Without policy edit flags, it shows an interactive picker with the current
allow and deny entries preselected.

```sh
licence_audit update
```

## Non-interactive edits

Use `--allow` or `--deny` to change policy from a script or CI job. These
options do not require a terminal or open the picker.

```sh
licence_audit update --allow=MIT,Apache-2.0 --deny=GPL-3.0-only
```

A supplied list replaces that list. An omitted list keeps its current value.
Use an empty value to clear a list:

```sh
# Replace allow and preserve deny.
licence_audit update --allow=MIT,ISC
# Clear deny and preserve allow.
licence_audit update --deny=
```

Comma-separated entries must be valid SPDX expressions. Spaces around entries
are removed. A whitespace-only value or an empty entry inside a non-empty list,
such as `--allow=MIT,,ISC`, is invalid and exits `2` without writing.
The command also rejects invalid existing configuration before discovery;
replacement flags do not repair it.

The output lists discovered licences, licences in neither list, and the
proposed allow and deny arrays. Uncovered licences do not block a write or
change a successful exit code of `0`. Use [`check`](/docs/check) to enforce
the policy.

## Preview without writing

Use `--dry-run` to discover licences and show the proposed edit without
changing or creating the policy file. No terminal is required.

```sh
# Preview the current lists.
licence_audit update --dry-run
# Preview a replacement allow list and an empty deny list.
licence_audit update --dry-run --allow=MIT,Apache-2.0 --deny=
```

Dry-run uses the same validation, replacement, and empty-list rules. It
validates the TOML edit and checks for concurrent policy changes, but does
not create a temporary policy file or attempt replacement. The preview shows
the two policy arrays; it does not print unrelated settings or exceptions.
Discovery can still use the metadata cache. Add `--no-cache` to bypass it.

## Update process

See [configuration discovery](/docs/configuration#discovery) for policy
selection and the [write target](/docs/configuration#update-write-target).

1. Without policy edit flags or an enabled `--dry-run`, `update` checks that
   stdin and stdout are interactive terminals.
2. It validates the target's TOML, policy, and exceptions.
3. It resolves the dependency tree and reads licence declarations from
   checksum-verified locked Hex archives.
4. It applies supplied lists, preserving omitted lists. In interactive mode,
   it shows a list of the licences. Existing allow and deny
   entries are preselected. Deny takes precedence if both lists match an entry.
   Equivalent SPDX spellings share one choice; custom reference case stays distinct.
5. It reads and validates the target again. If the allow or deny list changed
   during discovery or selection, it exits `2` with a conflict message.
   The newer file stays intact. Rerun `update` to review those rules.
6. It writes the result to the selected target, or prints a dry-run preview.
   Existing comments, formatting, and edits to unrelated settings stay intact.

For labels that fail SPDX expression parsing, `update` shows the raw text
above the picker or in the non-interactive output with an explanation. It
excludes these labels from selectable allow and deny entries, including the
bulk-selection keys. To accept a reviewed
invalid label, add an
[`invalid-licence-expression` exception](/docs/check#invalid-upstream-licence-labels)
for the exact package/version and raw text. The command does not convert informal
labels such as `Apache 2.0` into SPDX identifiers. Valid expressions with CRLF
token whitespace remain selectable.

Use `--config=PATH` to select an alternate target:

```sh
licence_audit update --config=policies/project.toml
```

`update` creates a missing policy section in a valid default or explicit target.
It can create a missing target file if the parent directory exists. It rejects
malformed TOML or invalid policy before fetching metadata or showing the picker.
It also rejects a target beneath an existing non-directory before these steps.
To change the starting selection, clear or change the preselected entries.
If you accept the selection without changes, the original allow and deny lists
are kept, including overlaps. This prevents an empty allow list from changing
the verdict for unrelated licences.
See [update migration](/docs/configuration#update-migration) for the removal of
`update --ignore-config`.

`update` preserves [scoped policy exceptions](/docs/check#scoped-policy-exceptions)
and their comments. It does not create, renew, or remove review decisions.
Malformed exception configuration returns exit code 2 before the interactive
selection or write. Use the audit report to find stale entries and remove
them from the configuration.

Successful writes exit `0`. Metadata discovery, configuration, TOML edit, and
file read/write failures exit `2`.

Discovery shares the [immutable metadata cache](/docs/#caching) with licence
reports, checks, and reproducible SBOMs. A cold cache requires larger archive
downloads. Missing checksums, checksum mismatches, and invalid or missing
archive metadata stop discovery before the picker or write. API licences
cannot replace this evidence.

An empty `allow` selection is saved, including a deny-only policy. `update`
warns that you must add allow rules before running `check` or `check --checks=all`.
Those commands require a non-empty allow list and otherwise exit `2`.
Vulnerability-only checks (`check --checks=vulns`) do not require an allow list.
Report-only use remains available. `--quiet` suppresses the warning with other
progress output.

The command writes a complete temporary file in the configuration directory
before an atomic replacement. It preserves file permissions and ownership.
A failed write leaves the original intact; forced termination can leave a
`*.licence-audit-*.tmp` file beside it.

On macOS, `update` cannot copy access control lists (ACLs). It uses the native
ACL listing to check the destination before writing. If an ACL is present or
the check fails, it exits `2` without replacing the original file. Its contents,
permissions, ownership, and access rules stay intact.

On Windows, replacement uses `MoveFileExW` through Windows PowerShell. Existing
owner, group, and access rules apply to the temporary file from creation,
before content is written. New policy files allow access only to the current
user. Timed-out helpers are terminated and awaited before temporary-file cleanup.
The command does not use OTP's non-atomic Windows rename.

## Terminal requirement

The picker requires a TTY. Explicit `--allow` or `--deny` edits and enabled
`--dry-run` do not:

- Without these options, it exits `2` if stdin or stdout is non-interactive.
  It prints one diagnostic to stderr before reading configuration or the
  manifest, opening the cache, or making network requests.
- It exits `130` if you cancel the picker.

> **Note:** If you use the escript, Erlang/OTP **28 or later** is required
> for all commands, not only interactive `update`. Unsupported OTP versions
> can fail before any command runs. The self-contained native binaries bundle
> the runtime. See the [installation requirements](/docs#install).

After you create a policy, enforce it with [`licence_audit
check`](/docs/check).

## Flags

<!-- cli-reference -->
Review discovered licences and update [tools.licence_audit]. Use --allow or --deny for non-interactive edits, or --dry-run to preview without writing. With none of these flags, use the interactive picker.

**Usage:**

```
licence_audit update [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--allow=<SPDX,...>` | `SPDX,...` |  | Replace the allow list with comma-separated SPDX expressions; an empty value clears it, omission preserves it |
| `--cache-dir=<DIR>` | `DIR` |  | Use DIR as the application cache root for all cache families |
| `--color=<auto\|always\|never>` | `auto\|always\|never` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config=<PATH>` | `PATH` |  | Read configuration from PATH |
| `--deny=<SPDX,...>` | `SPDX,...` |  | Replace the deny list with comma-separated SPDX expressions; an empty value clears it, omission preserves it |
| `--dry-run` | `BOOL` | `false` | Print discovered licences and the proposed policy edit without writing; no terminal required |
| `--manifest=<PATH>` | `PATH` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->
