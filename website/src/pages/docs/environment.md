---
layout: ../../layouts/DocsLayout.astro
title: Environment variables
description: Environment controls for cache discovery, reproducible timestamps, and destination-aware colour.
---

This table defines the CLI's environment-variable controls. **Unset** means
the variable does not exist; **empty** means it exists with value `""`.
These states differ for `FORCE_COLOR` and `CI`.

| Variable | Effect and precedence | Unset, empty, or other values |
|---|---|---|
| `XDG_CACHE_HOME` | With caching enabled and no `--cache-dir`, a nonempty value selects `<value>/licence_audit/`, before `HOME`, on all platforms. | Unset or empty falls through to `HOME`. Paths need not be absolute; the CLI does not trim whitespace. An unusable selected path causes a cache warning, not fallback to another root. |
| `HOME` | If `XDG_CACHE_HOME` is unset or empty, a nonempty value selects `<value>/.cache/licence_audit/`, including on macOS and Windows. | Unset or empty falls through to Windows user-cache discovery. Other platforms warn and continue without caching. Paths follow the same rules as `XDG_CACHE_HOME`. |
| `LOCALAPPDATA` | Only in Windows user-cache discovery, Erlang/OTP selects `<value>/licence_audit/Cache/` when both `LOCALAPPDATA` and `APPDATA` are nonempty. It ignores this variable when `--cache-dir`, `XDG_CACHE_HOME`, or `HOME` selects a root. | With nonempty `APPDATA`, unset or empty `LOCALAPPDATA` uses `<APPDATA>/licence_audit/Cache/`. Without nonempty `APPDATA`, OTP uses its home-based `Local/licence_audit/Cache/` fallback instead, even if `LOCALAPPDATA` is set. A non-absolute or unavailable resolved root causes a cache warning. |
| `SOURCE_DATE_EPOCH` | `sbom --reproducible` uses the parsed nonnegative integer as seconds since the Unix epoch, formatted in UTC. The timestamp also contributes to the content-derived `serialNumber`. | The CLI trims surrounding whitespace. Unset, empty, whitespace-only, non-integer, or negative values use `1970-01-01T00:00:00Z` without a warning or usage error. Without `--reproducible`, the CLI ignores this variable and uses the current time. |
| `NO_COLOR` | In `--color=auto`, any nonempty value disables colour before `FORCE_COLOR` or terminal detection. This includes `"0"` and `"false"`. | Unset or empty has no effect. The CLI does not trim whitespace, so `" "` disables colour. Explicit `--color=always` or `--color=never` overrides it. |
| `FORCE_COLOR` | In `auto`, after `NO_COLOR`, a set value overrides terminal detection, `TERM`, `COLORTERM`, and `CI`, including for pipes. Case-insensitive `"0"` or `"false"` disables colour; `"2"` and `"3"` request 256-colour and truecolour support. | Unset falls through to terminal detection. Empty and all other values enable basic colour, including `"1"`, `"true"`, and unrecognised values. No whitespace trimming or invalid-value error occurs. Explicit colour flags override it. |
| `TERM` | In `auto`, with no environment override and a terminal destination, exact `"dumb"` disables colour before `COLORTERM` or `CI`. Otherwise, a value containing `"256"` enables colour after `COLORTERM`. Matching is case-sensitive. | Unset, empty, and other values fall through to `CI` unless `COLORTERM` enables colour. `"xterm"` alone does not enable colour. This variable cannot enable colour in a pipe. |
| `COLORTERM` | After the terminal check and `TERM=dumb` check, case-insensitive `"truecolor"` or `"24bit"` enables colour before the `TERM` substring or `CI` checks. | Unset, empty, or unrecognised values fall through to `TERM` and `CI`. No whitespace trimming or invalid-value error occurs. It cannot enable colour in a pipe. |
| `CI` | After all earlier `auto` checks, its presence enables basic colour for a terminal destination. It does not disable colour or make a pipe a terminal. | Unset leaves colour disabled at this last step. Empty, `"0"`, `"false"`, and other set values enable colour. |

## Cache selection

Use `--cache-dir=DIR` to select the application root itself, without appending
`licence_audit/`. Each cache family uses a versioned subdirectory below that
root. An explicit root bypasses environment discovery. Relative roots resolve
from the command's working directory.

Use `--no-cache` to bypass reads and writes without deleting stored entries.
Combining enabled `--no-cache` with `--cache-dir` causes exit code `2` before
cache access; `--no-cache=false` does not conflict. Cache access failures warn
and let the command continue without the failed cache. `--quiet` hides these
warnings. Help and version requests do not open caches.

The Windows fallback delegates to Erlang/OTP's
[`filename:basedir(user_cache, "licence_audit")`](https://www.erlang.org/doc/apps/stdlib/filename.html#basedir/2).
`APPDATA` and the runtime's home directory participate in that fallback; they
are not additional licence policy or colour settings.
The Windows details above describe the delegated behavior in
[OTP 28](https://github.com/erlang/otp/blob/OTP-28.0/lib/stdlib/src/filename.erl)
and the pinned
[OTP 29.1.2](https://github.com/erlang/otp/blob/OTP-29.1.2/lib/stdlib/src/filename.erl).
They are not a portable fallback-path guarantee across runtime versions.
See [caching](/docs/#caching) for cache families and expiry rules.

## Colour selection

`--color` and its alias `--colour` accept `auto`, `always`, and `never`
without regard to case. Explicit `always` enables styling; explicit `never`
disables it. Both override the environment and terminal detection.

For `auto`, apply the table in this order: nonempty `NO_COLOR`, set
`FORCE_COLOR`, actual destination terminal status, exact `TERM=dumb`,
`COLORTERM`, the `"256"` substring in `TERM`, then presence of `CI`.
If the destination is not a terminal, stop with no colour after the first
two environment checks. If terminal detection fails, treat it as non-terminal.

The CLI detects stdout and stderr separately. Reports and successful help use
stdout; usage-error help, progress, and warnings use stderr. Redirecting one
stream does not change the other stream's colour decision. SBOM JSON and
notice payloads remain plain on stdout and in output files, including with
`always`. Colour support levels enable styling; they do not require report
renderers to emit 256-colour or truecolour escapes.

These rules match the current `tty` dependency and CLI stream behavior.
Dependency upgrades must preserve the documented controls under the
[compatibility policy](/docs/compatibility#guarantees-from-10).
