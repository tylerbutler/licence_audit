---
layout: ../../layouts/DocsLayout.astro
title: check
description: Report Hex package licence metadata and enforce your licence policy. Return a nonzero exit code for violations.
---

`check` runs the same audit as the command with no subcommand. It then
**enforces** your policy. It returns a nonzero exit code when it finds a
violation. Use `check` in CI.

```sh
licence_audit check
```

## Define a policy

Add the policy to `[tools.licence_audit]` in `gleam.toml`:

```toml
[tools.licence_audit]
allow = ["Apache-2.0", "MIT"]
deny  = ["GPL-3.0-only"]
```

An `allow` list permits only the specified licences. A `deny` list rejects
matching licences. To create the policy, use [`licence_audit
update`](/docs/update). The command gets metadata, selects existing entries,
asks you to confirm the selection, and writes the result. It preserves
comments in `gleam.toml`.

### SPDX expressions

`AND` requires both terms to pass. `OR` needs one passing alternative.
With the policy above, `MIT AND GPL-3.0-only` fails, but
`MIT OR GPL-3.0-only` passes through MIT. The same branch must satisfy both
the allow and deny rules.

Operators must be uppercase. `WITH` binds first, then `AND`, then `OR`;
parentheses change grouping. Treat `GPL-2.0-only WITH Classpath-exception-2.0`
as one term: allowing or denying bare `GPL-2.0-only` does not match it.
A trailing `+` is also part of the term. Use the complete term in your policy.
SPDX identifiers match without regard to case; custom `LicenseRef-`
identifiers remain case-sensitive. The parser checks syntax, not membership
in the SPDX licence list. It does not infer equivalence between identifiers.

Separate strings in a package's licence list must all pass. An exact
expression in `allow` accepts its terms but does not override operand deny
rules. An exact expression in `deny` rejects that declaration.
Expression matching ignores whitespace between tokens and SPDX identifier
case, but preserves custom-reference case and the expression's tokens.

Malformed expressions fail the gate, even with a deny-only policy.
For untrusted metadata, the parser limits each expression to 64 KiB,
1024 tokens, and 64 nested parentheses. Expressions above these limits fail
the gate.

## Ad-hoc and merged policy

The command merges CLI `--allow` and `--deny` values with the configuration.
Use these options to add restrictions for one run:

```sh
licence_audit check --allow=Apache-2.0,MIT --deny=GPL-3.0-only
```

Use `--config=other.toml` to read a different file. The file must have a
`[tools.licence_audit]` section. Use `--ignore-config` to use only CLI options.

> **Note:** `--allow` and `--deny` also work on the bare command. These options
> show a policy preview, but the command returns exit code 0. Use `check` to
> return a failure for a violation.

## Production-only gates

Use `--prod-only` when your gate should consider only production dependencies.
The command then ignores licence violations in development dependencies. This
option prevents tooling-only packages from causing a CI failure.

## Also fail on vulnerabilities

Add `--vulns` to run the licence audit and query OSV.dev. The command fails
when an advisory meets or exceeds the severity threshold:

```sh
licence_audit check --vulns
licence_audit check --vulns --vuln-severity=medium
licence_audit check --vulns --vuln-block-unknown
```

The threshold is `low` \| `medium` \| `high` (default) \| `critical`.
The command reports advisories with unknown severity, but these advisories do
not cause a failure by default. Use `--vuln-block-unknown` to make these
advisories cause a failure. `check --vulns` fails if it cannot connect to OSV.dev
because it cannot complete the check. You can set the threshold in the
configuration:

```toml
[tools.licence_audit]
vuln_severity = "high"
vuln_block_unknown = true
```

`--vuln-severity` overrides the configured threshold. `--vuln-block-unknown`
can only enable blocking: if you omit it, a configured `true` still applies.
There is no CLI flag to turn this setting off. Use `--ignore-config` to ignore
both configured vulnerability settings and use CLI-only defaults, which do
not block unknown severity.

## Scoped policy exceptions

Record an exception to accept one finding at one locked version. Keep the
entry in version control so reviewers can read the reason.

```toml
[[tools.licence_audit.exceptions]]
purl = "pkg:hex/example@1.2.3"
finding = "denied-licence"
licence = "GPL-3.0-only"
reason = "Approved for this release while we replace the dependency."
expires = "2026-12-31"

[[tools.licence_audit.exceptions]]
purl = "pkg:hex/example@1.2.3"
finding = "advisory"
advisory = "CVE-2026-12345"
reason = "Reviewed the affected feature; this application does not use it."
expires = "2026-12-31"
```

Put global settings such as `allow`, `deny`, and `vuln_severity` in
`[tools.licence_audit]`, before the exception tables. Each exception requires
`purl`, `finding`, and a non-empty `reason`.

| `finding` | Additional field | What it accepts |
|---|---|---|
| `denied-licence` | `licence = "GPL-3.0-only"` | A matching declared licence rejected by `deny`. |
| `unallowed-licence` | `licence = "Apache-2.0"` | A matching declared licence absent from a non-empty `allow` list. |
| `no-licences-declared` | None | A successful metadata response with an empty licence list. |
| `advisory` | `advisory = "CVE-2026-12345"` | An OSV advisory ID or a direct alias in the fetched record. |

Use the licence term from the finding in the report, rather than the full
declared expression. A denied term takes precedence over an unallowed term.
An exception for one selector cannot accept another selector, a second
required term, or another advisory. For `OR`, an accepted alternative is
sufficient. The report prefers an alternative that passes global policy over
one that needs an exception. Malformed expressions cannot be excepted.

### Exact package scope

Licence exceptions require `pkg:hex/<name>@<exact-version>`. Advisory exceptions
also accept `pkg:github/<owner>/<repo>@<full-commit>`, for example:

```toml
[[tools.licence_audit.exceptions]]
purl = "pkg:github/owner/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
finding = "advisory"
advisory = "GHSA-xxxx-yyyy-zzzz"
reason = "Reviewed the affected code at this commit."
```

Copy the full locked commit, not a branch, tag, or abbreviated hash. Use
lowercase package identities and full hexadecimal Git object IDs (40 or 64
characters). Hex versions support exact prerelease and build suffixes.
Wildcards, version ranges, purl qualifiers, subpaths, and other sources are
not supported. A version or commit update does not inherit the old exception.

Advisory IDs are case-sensitive. Match only the record's primary ID or its
explicit `aliases`; related IDs, text mentions, and alias chains do not
match. The same advisory on another package still uses the normal gate.
Two entries that select the same scoped finding cause a configuration error,
including entries that overlap through advisory aliases. Remove one entry
instead of relying on file order.

### Precedence and expiry

The command evaluates global rules first, then applies each matching
exception. An active exception can accept an explicit deny, including a deny
added through the CLI. It does not modify the global lists or declared
metadata. Exceptions alone do not replace the licence policy required by
`check`. `--ignore-config` ignores the exceptions along with other settings.

Set `expires = "YYYY-MM-DD"` for a temporary waiver. The date must be a valid,
quoted calendar date. An exception dated `2026-12-31` remains active through
that UTC date and stops applying at `2027-01-01T00:00:00Z`. The command reads
the system clock once per run; reproducible-build timestamps do not affect
expiry. Omit `expires` for an indefinite review decision.

### Review report and stale entries

The report retains each accepted finding and marks it `excepted`, with the
reason and expiry. A package with both accepted and blocking findings still
fails the gate. Accepted findings remain visible when another dependency tree
fails and when you use `--quiet`.

The exception summary reports `expired` entries and stops applying them.
It reports `unused` when a completed scan finds no matching package or
finding. Remove these stale entries after a dependency update, resolved
advisory, or global policy change. Expired and unused entries do not fail on
their own; matching expired findings follow normal policy and severity rules.

An entry is `not evaluated` if its scan is disabled, `--prod-only` excludes
the package, or the command cannot get the evidence. Do not treat these
entries as stale. Licence-only runs do not evaluate advisory exceptions.
The bare command previews licence exceptions without enforcing them, and
[`vulns`](/docs/vulns) displays advisory exceptions without enforcing a gate.

Exceptions cannot accept failed network requests, malformed metadata, missing
advisory details, or unsupported source coverage. They do not change SBOM
evidence, remove notice content, or remove licence-text and attribution
requirements. `update` preserves exception entries and their comments.

## Flags

| Flag | What it does |
|---|---|
| `--allow` | Allow licences, comma-separated. Merges with config. |
| `--deny` | Deny licences, comma-separated. Merges with config. |
| `--prod-only` | Only audit production dependencies. |
| `--vulns` | Also query OSV.dev and fail on advisories at or above `--vuln-severity`. |
| `--vuln-severity` | Minimum failing severity: `low` \| `medium` \| `high` (default) \| `critical`. |
| `--vuln-block-unknown` | Fail `check --vulns` on advisories with unknown severity. |
| `--config` | Read configuration from `PATH`. |
| `--ignore-config` | Ignore configuration files; use only CLI flags. |
| `--manifest` | Read `manifest.toml` from `PATH`. |
| `--cache-path` | Override the licence metadata cache location. |
| `--no-cache` | Bypass the on-disk licence metadata cache. |
| `--color` | Colourise output: `auto` (default) \| `always` \| `never`. Alias `--colour`. |
| `--quiet` / `--verbose` | Suppress or expand progress output. |
