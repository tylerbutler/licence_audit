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

1. `update` resolves the dependency tree and gets licence metadata from Hex.
2. It shows an interactive list of the licences. Existing allow and deny
   entries are preselected.
3. It writes the result to `gleam.toml`. Existing comments and formatting do
   not change.

`update` preserves [scoped policy exceptions](/docs/check#scoped-policy-exceptions)
and their comments. It does not create, renew, or remove review decisions.
Malformed exception configuration returns exit code 2 before the interactive
selection or write. Use the audit report to find stale entries and remove
them from the configuration.

Successful writes exit `0`. Metadata discovery, configuration, TOML edit, and
file read/write failures exit `2`.

The command writes a complete temporary file in the configuration directory
before an atomic replacement. It preserves file permissions and ownership.
A failed write leaves the original intact; forced termination can leave a
`*.licence-audit-*.tmp` file beside it.

On Windows, replacement uses `MoveFileExW` through Windows PowerShell. Existing
owner, group, and access rules apply to the temporary file from creation,
before content is written. New policy files allow access only to the current
user. Timed-out helpers are terminated and awaited before temporary-file cleanup.
The command does not use OTP's non-atomic Windows rename.

## Terminal requirement

`update` is interactive and requires a TTY:

- It exits `1` on non-interactive stdin (for example, in CI).
- It exits `130` if you cancel.

> **Note:** The interactive list requires Erlang/OTP **28.x or newer**.
> Earlier releases cannot reattach stdin in raw mode. As a result, the list
> does not receive keyboard input. If `update` does not respond to keyboard
> input, check your OTP version.

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
| `--cache-path` | `STRING` |  | Override the licence metadata cache location |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--quiet` | `BOOL` | `false` | Suppress progress output |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
<!-- cli-referencestop -->
