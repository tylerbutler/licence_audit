---
layout: ../../layouts/DocsLayout.astro
title: update
description: Interactively review the discovered licences and write a policy into your gleam.toml.
---

`update` is the friendly way to create a policy. It fetches licence metadata,
shows you every licence in your tree, preselects any entries already in your
config, and writes your choices back to `[tools.licence_audit]` in `gleam.toml`
— comments preserved.

```sh
licence_audit update
```

## What it does

1. Resolves your dependency tree and fetches licence metadata from Hex.
2. Presents an interactive picker of the discovered licences, with existing
   allow / deny entries preselected.
3. Writes the result back into `gleam.toml` without disturbing your existing
   comments or formatting.

## It needs a real terminal

`update` is interactive, so it needs a TTY:

- It exits `1` on non-interactive stdin (for example, in CI).
- It exits `130` if you cancel.

> **Heads up** — the interactive picker needs Erlang/OTP **28.x or newer**.
> Earlier releases can't reattach stdin in raw mode, so the picker won't receive
> keyboard input. If `update` doesn't react to keystrokes, check your OTP
> version.

Once you've captured a policy, enforce it with [`licence_audit
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
