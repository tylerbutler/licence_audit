---
layout: ../../layouts/DocsLayout.astro
title: Configuration
description: Select the project configuration and understand explicit policy files.
---

## Discovery

`licence_audit` uses the directory that contains the selected manifest as the
project root. Without `--manifest`, it reads `manifest.toml` in your current
directory. With `--manifest=PATH`, it reads that path and uses its directory.
With `--manifest=DIR`, it reads `DIR/manifest.toml` and uses `DIR` as the
project root. Both forms use the same configuration and dependency paths.
Relative manifest and configuration paths start from your current directory.

The default configuration file is `gleam.toml` beside that manifest:
`<project root>/gleam.toml`. The command does not search parent directories
or fall back to your current directory's `gleam.toml`.

```sh
# Read apps/server/manifest.toml and apps/server/gleam.toml
licence_audit check --manifest=apps/server/manifest.toml
# Equivalent directory form
licence_audit check --manifest=apps/server
```

If the manifest is missing, the error names its directory and suggests running
`gleam deps download` or selecting another manifest with `--manifest=PATH`.
Run `gleam deps download` in the project root to create the manifest.
The command does not search parent directories for a manifest.
Unreadable files and invalid manifest contents remain separate errors.

These commands use the same project-root rule, but read different settings:

| Command | Configuration use |
|---|---|
| Bare invocation or `report` | Read `[tools.licence_audit]` for a policy preview. |
| `check` | Read `[tools.licence_audit]` and enforce the policy. |
| `update` | Read the existing policy, then select, replace, or preview its lists. |
| `vulns` | Read policy exceptions for the advisory report; do not enforce licence rules. |
| `notices` | Read `[tools.licence_audit.notices]` dependency filters; do not enforce licence rules. |
| `sbom` | Read project metadata for the root component; do not read or enforce licence policy. |

If the default configuration file or policy section is absent, reporting can
proceed without a policy. Licence-only and combined checks require a licence
policy from the selected file. Vulnerability-only checks do not require one.
`update` can create the section in the project's `gleam.toml`.
Invalid configuration still causes an error.
For an invalid SPDX expression in `allow` or `deny`, the diagnostic names the
field and the exact parsed entry, including whitespace.
To accept an invalid upstream label, add a reviewed
[`invalid-licence-expression` exception](/docs/check#invalid-upstream-licence-labels)
for its exact package/version and raw text. This exception does not make invalid
entries valid in `allow` or `deny`.

## Explicit configuration files

On commands that accept `--config`, use it to select a different file instead
of the default policy file:

```sh
licence_audit check --manifest=apps/server/manifest.toml --config=policies/server.toml
```

For the default report, `report`, licence-only or combined `check`, and `vulns`,
the explicit file must
contain `[tools.licence_audit]`. A file without this section causes an error
with exit code `2`. The error names the file and missing section.
An empty section counts as present, but does not
supply the licence rules that licence-only and combined checks require.
`check --checks=vulns` accepts a valid file without this section.

```toml
[tools.licence_audit]
allow = ["MIT", "Apache-2.0"]
deny = ["GPL-3.0-only"]
```

`notices` reads only its filter settings. A valid TOML file without
`[tools.licence_audit.notices]` means no filters; it does not require a licence
policy section.

`update` can create `[tools.licence_audit]` in a valid explicit target without
that section. It can also create a missing target file if its parent directory
exists.

Selecting another configuration file does not change the project root.
Dependency scope and project metadata still come from the `gleam.toml` beside
the manifest. `sbom` does not accept `--config`; it uses that project's metadata.

## Policy selection and ignoring configuration

Reports and checks read `allow` and `deny` from the selected TOML file.
Use `--config=policies/release.toml` to select an alternate policy.
Edit the TOML file, use the `update` picker, or supply `update --allow=...`
and `--deny=...` to change the lists.
See [policy rules](/docs/check) for how the lists affect findings.

On read-only commands that accept `--ignore-config`, this option bypasses tool
configuration reads, including exceptions and notices filters. Do not combine
enabled `--ignore-config` with `--config`; the command rejects this pair with
exit code `2`. Explicit `--ignore-config=false` permits `--config`.
Ignoring configuration does not disable project metadata reads.

```sh
licence_audit --ignore-config
```

This produces a licence report without policy findings. Licence-only and
combined checks with `--ignore-config` return exit code `2` because licence
enforcement requires a non-empty `allow` list from a policy file.
Vulnerability-only checks can use `--ignore-config` without licence rules.
Read-only commands do not change the selected file.

## Update write target

`update` writes to the file selected by `--config`, or to the `gleam.toml`
beside the manifest if you omit `--config`. It creates a missing policy section
in either target. A missing target file is a supported creation case if its
parent directory exists.

Before fetching metadata or showing the picker, `update` validates the target's
TOML, existing policy, and exceptions. Invalid input causes exit code `2` and
leaves the file intact. The picker preselects valid allow and deny entries; you
can clear or change them. The command preserves unrelated settings, comments,
exceptions, and permissions with an atomic replacement.

For non-interactive edits, a supplied `--allow` or `--deny` replaces that list;
an omitted flag preserves it. `--allow=` or `--deny=` clears the respective
list. Empty entries inside a non-empty comma-separated list remain invalid.
All entries must pass the same SPDX validation as configuration files.
The command preserves exception entries and vulnerability settings.

```sh
# Create or update the policy in an alternate target.
licence_audit update --config=policies/server.toml
# Replace allow in that target and keep its deny list.
licence_audit update --config=policies/server.toml --allow=MIT,Apache-2.0
# Preview clearing deny without changing the file.
licence_audit update --config=policies/server.toml --deny= --dry-run
```

Explicit edits and dry-run do not require a terminal. Dry-run validates and
prints the proposed edit without changing or creating the target file.
`update` reports discovered licences in neither list, but these licences do
not prevent a successful write or cause a failed exit. Use `check` to enforce
the saved policy. See [the update guide](/docs/update#non-interactive-edits)
for the output and failure rules.

## Update migration

Remove `--ignore-config`, including `=true` and `=false`, from `update` commands.
`update` has no alias for this flag. To start a new selection, clear the
preselected entries in the picker, or supply `--allow=` and `--deny=` to clear
both lists without a terminal. To initialize an existing target without a
policy section, use `update --config=PATH`; no bypass flag is needed.
Read-only commands keep `--ignore-config`.
