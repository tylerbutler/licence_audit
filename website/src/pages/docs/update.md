---
layout: ../../layouts/DocsLayout.astro
title: update
description: Select the discovered licences and write a policy to your Gleam configuration.
---

Use `update` to create a policy. It gets licence metadata and shows each
licence in the dependency tree. It preselects the entries that are already in
your configuration. It then writes your choices to `[tools.licence_audit]` in
`gleam.toml` and preserves comments.

```sh
licence_audit update
```

## Update process

See [configuration discovery](/docs/configuration#discovery) for policy
selection and the [write target](/docs/configuration#update-write-target).

1. `update` checks that stdin and stdout are interactive terminals.
2. It validates the target's TOML, policy, and exceptions.
3. It resolves the dependency tree and reads licence declarations from
   checksum-verified locked Hex archives.
4. It shows an interactive list of the licences. Existing allow and deny
   entries are preselected. Deny takes precedence if both lists match an entry.
   Equivalent SPDX spellings share one choice; custom reference case stays distinct.
5. It reads and validates the target again. If the allow or deny list changed
   during selection, it exits `2` with a conflict message. The newer file stays
   intact. Rerun `update` to review those rules.
6. It writes the result to the selected target. Existing comments, formatting,
   and edits to unrelated settings stay intact.

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

`update` is interactive and requires a TTY:

- It exits `2` if stdin or stdout is non-interactive (for example, in CI).
  It prints one diagnostic to stderr before reading configuration or the
  manifest, opening the cache, or making network requests.
- It exits `130` if you cancel.

> **Note:** If you use the escript, Erlang/OTP **28 or later** is required
> for all commands, not only interactive `update`. Unsupported OTP versions
> can fail before any command runs. The self-contained native binaries bundle
> the runtime. See the [installation requirements](/docs#install).

After you create a policy, enforce it with [`licence_audit
check`](/docs/check).

## Flags

<!-- cli-reference -->
Interactively review discovered licences and write an updated [tools.licence_audit] policy to gleam.toml.

**Usage:**

```
licence_audit update [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-dir` | `STRING` |  | Use DIR as the application cache root for all cache families |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->
