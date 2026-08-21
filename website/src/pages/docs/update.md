---
layout: ../../layouts/DocsLayout.astro
title: update
description: Select the discovered licences and write a policy to your Gleam configuration.
---

Use `update` to create a policy. It gets licence metadata and shows each
licence in the dependency tree. It selects entries that are already in your
configuration. It then writes your choices to `[tools.licence_audit]` in
`gleam.toml` and preserves comments.

```sh
licence_audit update
```

## What it does

1. Resolves the dependency tree and gets licence metadata from Hex.
2. Shows an interactive list of the licences. The list selects existing allow
   and deny entries.
3. Writes the result to `gleam.toml` without changing existing comments or
   formatting.

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

| Flag | What it does |
|---|---|
| `--config` | Read configuration from `PATH`. |
| `--ignore-config` | Ignore configuration files when preselecting entries. |
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--cache-path` | Override the licence metadata cache location. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--color` | Colourise output: `auto` (default) \| `always` \| `never`. Alias `--colour`. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |
