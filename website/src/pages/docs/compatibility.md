---
layout: ../../layouts/DocsLayout.astro
title: Compatibility policy
description: CLI and configuration compatibility guarantees from licence_audit 1.0.0 onward.
---

This policy defines the compatibility promise for `licence_audit` from version
1.0.0 onward. It does not add features to the current release. Before 1.0.0,
minor releases can include breaking changes; consult the release notes before
you upgrade.

The CLI is the only supported interface. We do not provide a supported Gleam
library API.

## Versioning

We use [Semantic Versioning](https://semver.org/):

- Patch releases fix defects without deliberate changes to the supported
  interface, subject to the correctness and security exceptions below.
- Minor releases can add compatible commands, options, and configuration.
- Major releases can change or remove supported interfaces.

Within `1.x`, we preserve existing documented CLI and configuration behavior.
New settings use defaults that preserve existing behavior. A deliberate change
to policy semantics or enforcement defaults requires an opt-in during `1.x`,
or a new major release.

We document deprecations and migration steps in release notes. Deprecated
interfaces remain usable until the next major release.

## Commands and configuration

Existing documented commands, flags, aliases, and valid argument forms remain
available within a major version. We preserve their meanings, defaults, and
documented environment-variable controls.

Existing valid configuration remains valid with the same meaning. This includes
configuration discovery, CLI/config precedence, and merge behavior. We can
reject invalid input that an earlier version accepted because of a defect.

Compatibility works in the upgrade direction: an older release does not have
to accept options or configuration introduced in a newer release.

## Exit codes and output streams

We preserve the documented exit-code categories:

| Code | Meaning |
| ---- | ------- |
| `0` | Successful completion. Report-only commands do not fail because they find policy violations or vulnerabilities. |
| `1` | An enforced gate failed, CLI usage was invalid, or `update` could not run with non-interactive stdin. |
| `2` | An input, configuration, manifest, network, decode, or artifact-generation error prevented completion. |
| `130` | The user cancelled `update`. |

A report-only command can still fail when it cannot complete its work.
Missing or invalid policy configuration is an error, not a passing check.

Reports and generated artifacts go to stdout unless the user selects an output
file. Progress, warnings, and errors go to stderr. Commands that support
`--output` keep stdout empty when they write the artifact to that file.

Use exit codes to determine command status. Do not parse diagnostic messages.

## Human-readable output

We can change report wording, table layout, ordering, colors, progress messages,
and interactive presentation within a major version. These are not parsing
interfaces.

The notice document's exact layout is also not stable. We can improve licence
material selection and attribution handling without preserving previous text
byte for byte.

## Structured output

For SBOMs, we preserve support for the documented CycloneDX version and keep
output valid against that version's schema. We can add schema-permitted fields
and improve metadata. We do not promise a fixed JSON layout, field order, or
identical bytes across tool releases. A new default CycloneDX version requires
a major release; a minor release can offer another version through opt-in.

Audit/check and vulnerability reports do not currently have a supported JSON
format. If we add one, we will give its schema an explicit version. Within a
schema version, we will preserve existing field names, types, meanings, and
required fields. Consumers must tolerate additional fields. We will document
any extensible value sets before adding values to them.

An incompatible report schema requires a new schema version. Within a major
CLI version, we will preserve the old schema and default, and make the new
schema opt-in.

## Audit results and correctness fixes

A stable interface does not guarantee the same audit result on later runs.
Package maintainers can update metadata, and advisory databases can add or
correct vulnerabilities. Network availability and cache freshness can also
affect a run.

We can ship correctness and security fixes in patch releases even when they
change a verdict or generated artifact. Examples include correcting severity
calculation, finding an advisory that we previously missed, or rejecting
malformed data that we previously accepted. We identify these changes and
their effects in release notes.

This exception does not permit unrelated policy redesign or new enforcement
defaults in a patch release.

For `sbom --reproducible`, reproducibility requires the same tool version,
input files, resolved metadata, options, and relevant environment values,
including `SOURCE_DATE_EPOCH`. A fixed lockfile alone does not freeze external
metadata. Reproducibility does not extend across tool versions.

## Internal details

We can change Gleam modules and functions, dependencies, build internals, and
on-disk cache formats without a major release. Do not import internal modules
or read cache files as an integration interface.

Cache format upgrades must not require manual repair. The CLI must migrate
incompatible entries or treat them as misses. A cache miss can require a new
network request.

This policy does not expand dependency-source coverage or platform support.
Consult the documentation for the installed release for those limits.
