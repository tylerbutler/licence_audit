---
layout: ../../layouts/DocsLayout.astro
title: Configuration
description: Select the project configuration and understand explicit policy files.
---

## Discovery

`licence_audit` uses the directory that contains the selected manifest as the
project root. Without `--manifest`, it reads `manifest.toml` in your current
directory. With `--manifest=PATH`, it reads that path and uses its directory.
Relative manifest and configuration paths start from your current directory.

The default configuration file is `gleam.toml` beside that manifest:
`dirname(--manifest)/gleam.toml`. The command does not search parent directories
or fall back to your current directory's `gleam.toml`.

```sh
# Read apps/server/manifest.toml and apps/server/gleam.toml
licence_audit check --manifest=apps/server/manifest.toml
```

These commands use the same project-root rule, but read different settings:

| Command | Configuration use |
|---|---|
| `licence_audit` (no subcommand) | Read `[tools.licence_audit]` for a policy preview. |
| `check` | Read `[tools.licence_audit]` and enforce the policy. |
| `update` | Read the existing policy to preselect entries, then write the selected policy. |
| `vulns` | Read policy exceptions for the advisory report; do not enforce licence rules. |
| `notices` | Read `[tools.licence_audit.notices]` dependency filters; do not enforce licence rules. |
| `sbom` | Read project metadata for the root component; do not read or enforce licence policy. |

If the default configuration file or policy section is absent, reporting can
proceed without a policy. `check` requires a licence policy from the file or
CLI flags. `update` can create the section in the project's `gleam.toml`.
Invalid configuration still causes an error.

## Explicit configuration files

On commands that accept `--config`, use it to select a different file instead
of the default policy file:

```sh
licence_audit check --manifest=apps/server/manifest.toml --config=policies/server.toml
```

For the audit report, `check`, `update`, and `vulns`, the explicit file must
contain `[tools.licence_audit]`. A file without this section causes an error
with exit code `2`, even when CLI flags supply a policy. The error names the
file and missing section. An empty section counts as present, but does not
supply the licence rules that `check` requires.

```toml
[tools.licence_audit]
allow = ["MIT", "Apache-2.0"]
deny = ["GPL-3.0-only"]
```

`notices` reads only its filter settings. A valid TOML file without
`[tools.licence_audit.notices]` means no filters; it does not require a licence
policy section.

Selecting another configuration file does not change the project root.
Dependency scope and project metadata still come from the `gleam.toml` beside
the manifest. `sbom` does not accept `--config`; it uses that project's metadata.

## CLI policy and ignoring configuration

CLI `--allow` and `--deny` values add to their corresponding configured lists.
The command removes duplicates; the CLI lists do not replace the file lists.
See [policy rules](/docs/check) for how the combined lists affect findings.

On commands that accept `--ignore-config`, this option bypasses tool
configuration reads, including exceptions and notices filters. It takes
precedence over `--config`: the command does not read or validate the named
policy file. It does not disable project metadata reads.

```sh
licence_audit check --ignore-config --allow=MIT,Apache-2.0
```

## Update write target

`update` writes to the file selected by `--config`, or to the `gleam.toml`
beside the manifest if you omit `--config`. `--ignore-config` clears the
preselection but does not change this write target.

If an explicit target exists but has no policy section, `update` fails before
fetching metadata, showing the picker, or writing the file. Use
`--ignore-config` to start a new selection in that file. A missing target file
is a supported creation case for `update`; its parent directory must exist.
The command preserves unrelated configuration and comments when it writes.
