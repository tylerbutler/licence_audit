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

## Canonical documentation

The [documentation website](/docs) is the canonical source for user-facing
CLI and configuration behavior. Its source is `website/src/pages/docs/**`.
Usage and flag tables are generated from the CLI definitions; the surrounding
guides explain configuration, command behavior, and limits. CI checks the
generated sections for drift and checks and builds the website.

The repository README and command files in `docs/` link to these guides.
They are not separate compatibility contracts. Release notes and contributor
decision records describe changes or design history, not additional CLI
interfaces.

Compatibility applies to the documentation and CLI definitions for the
installed release. The latest website can describe options introduced after
an older release; use that release's tagged website sources and its `--help`
output when checking an older installation.

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

### Pre-1.0 dependency scope migration

Replace `--prod-only` with `--scope=prod` for licence reports, `check`, and
`vulns`. These commands default to `--scope=all`. Replace
`notices --include-dev` with `notices --scope=all`; notices still defaults to
`--scope=prod`.

The removed flags are usage errors, including `=true` and `=false` forms.
Where a script used `--prod-only=false`, use `--scope=all`. Where it used
`notices --include-dev=false`, use `notices --scope=prod`. Configuration
filters cannot add development-only packages under production scope.

Neither `sbom` nor `update` accepts `--scope`. SBOM output retains the full
locked graph and each component's production or development scope.

## Commands and configuration

`licence_audit report` is an explicit form of the default licence report.
Bare invocation and root scan flags remain supported, except for the removed
policy flags below. Both forms use the same report options and behavior.
There is no `audit` alias. Root `--help`, `-h`, and `--version` still work
without reading project files or making network calls.

### Migration before 1.0

The licence report and `check` reject `--allow` and `--deny`, including empty
values. They have no aliases. Ad-hoc CLI additions can no longer widen a
configured allow list or add deny rules for one run.

Move those entries into `[tools.licence_audit]` in a TOML file, then select it:

```toml
[tools.licence_audit]
allow = ["MIT", "Apache-2.0"]
deny = ["GPL-3.0-only"]
```

```sh
licence_audit check --config=policies/release.toml
licence_audit --config=policies/release.toml
licence_audit report --config=policies/release.toml
```

Include the complete policy in the alternate file; its lists replace the
default file selection. Keep the file in version control for review.
Use interactive `update` or edit TOML to change it. `update` does not provide
non-interactive list editing flags.

Reports can run without policy, including with `--ignore-config`. Licence
enforcement requires a non-empty configured `allow` list, so licence-only and
combined checks with `--ignore-config` return exit code `2`.
Vulnerability-only checks do not require licence policy.

### Guarantees from 1.0

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
| `1` | An enforced gate failed. |
| `2` | Invalid CLI usage or an input, configuration, manifest, network, decode, or artifact-generation error prevented completion. This includes `update` without interactive stdin and stdout. |
| `130` | The user cancelled `update`. |

These categories apply after the CLI starts on a supported runtime. Escript
installations require Erlang/OTP 28 or newer for every command. An unsupported
runtime can fail while loading the program, before CLI error handling starts
(for example, a corrupt atom table error with exit `127`). Such failures are
outside this exit-code contract. Prefer a self-contained executable for CI.

A report-only command can still fail when it cannot complete its work.
Missing or invalid policy configuration is an error, not a passing check.

Licence reports exit `2` if required package metadata cannot be fetched or
decoded, even when they show results for other packages. Policy findings in a
completed report still exit `0`. `update` TOML edit and file-write failures
also exit `2`, not the gate-failure category `1`.

### Pre-1.0 usage migration

Update scripts to treat exit `1` as an enforced gate failure and exit `2` as
an error. Unknown flags or commands, invalid flag values, conflicting flags,
unexpected positional arguments, and non-interactive `update` now exit `2`
instead of `1`. User cancellation of `update` still exits `130`.

Remove one flag from each contradictory pair. Commands that accept both
`--config` and `--ignore-config` reject the pair when `--ignore-config` is
enabled. To read the selected file, remove `--ignore-config`; to ignore
configuration, remove `--config`. Commands that accept `--no-cache` and
`--cache-dir` reject the pair when `--no-cache` is enabled. To use the cache
root, remove `--no-cache`; to bypass storage, remove `--cache-dir`.
Explicit `--ignore-config=false` and `--no-cache=false` do not conflict with
their path flags.

### Completion and output

Optional enrichment has separate completion rules:

- `vulns` and `sbom --vulns` tolerate individual advisory-detail failures:
  they warn and retain the advisory ID with unknown severity, then exit `0`.
  An OSV batch request failure exits `2`. `check --checks=vulns` and
  `check --checks=all` also exit `2` when
  advisory details are unavailable because the gate cannot evaluate severity.
- Default `sbom` generation tolerates missing Hex or local Git dependency
  enrichment: it warns, omits unavailable fields, and exits `0`. `--offline`
  prohibits network requests and reads local files and usable cached evidence.
  `--reproducible` requires locked Hex/Git metadata, including offline.
  Local metadata, locked identities, paths, and edges must be valid in each
  mode; local cycles fail. Local components require publication verification:
  positive records do not expire, and negative records expire at 24 hours.
  Missing required metadata, verification, or requested pinned SPDX text
  exits `2`; `--offline` and `--no-cache` do not waive these requirements.
  Root metadata, supported sources, and artifact generation/writes remain required.

These exit-code corrections precede the 1.0 contract: incomplete licence
reports previously exited `0`, and `update` edit/write failures exited `1`.
Scripts that relied on those codes must use `2` for operational failure.

Before 1.0, `sbom --offline` changes from enrichment skipping to network
prohibition. Warm the selected `--cache-dir` with the required online options
before running offline. `--licence-text --offline` now accepts cached pinned
text; missing text returns `2`. Reproducible offline runs no longer succeed
by omitting required locked metadata.

Reports, gate verdicts, and generated artifacts go to stdout unless the user
selects an output file. Progress, warnings, and operational errors go to stderr.
Commands that support `--output` keep stdout empty when they write the artifact
to that file.

Reports stay on stdout even when an enforced gate fails or a report is
incomplete. A completed `check` that fails a licence or vulnerability policy
prints its verdict after the report and exits `1`, without a duplicate stderr
error. Operational failures, such as OSV batch or advisory-detail request
failures, go to stderr and exit `2`; any available report and exception
coverage stay on stdout.

`--quiet` hides INFO and WARN messages on stderr, but never errors. Erlang
runtime reports, including native-library load errors, also go to stderr.
If SBOM generation fails before a document is available, stdout stays empty.

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
project files, lockfile, options, and relevant environment values, including
`SOURCE_DATE_EPOCH`, plus matching usable publication evidence for local
components. Hex metadata comes from
checksum-verified locked package archives and Git metadata comes from the
archive at the locked commit, or their immutable cache entries. Offline runs
require the same evidence without network requests. The command reads local
path metadata from current `gleam.toml` files without caching it. Local references use normalized manifest-relative paths; local
source contents are not hashed or attested. Mutable Hex publisher and OSV advisory data are not
included. Refreshing expired negative publication evidence can add a purl
without changing local files; the manifest alone does not fix output over
time. Reproducibility does not extend across tool versions.

## Internal details

We can change Gleam modules and functions, dependencies, build internals, and
on-disk cache formats without a major release. Do not import internal modules
or read cache files as an integration interface.

Cache format upgrades must not require manual repair. The CLI must migrate
incompatible entries or treat them as misses. A cache miss can require a new
network request.

This policy does not expand dependency-source coverage or platform support.
Consult the documentation for the installed release for those limits.
