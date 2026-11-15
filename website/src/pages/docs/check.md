---
layout: ../../layouts/DocsLayout.astro
title: check
description: Select licence checks, vulnerability checks, or both. Return a nonzero exit code for violations.
---

Use `check` in CI to enforce the selected gates. Select them with
`--checks=licences|vulns|all`. The default is `licences`.
Licence checks run the same scan as [`report`](/docs/report), then enforce
your policy. A gate violation returns a nonzero exit code.

The licence verdict uses declarations from the checksum-verified locked Hex
archive, even if the Hex API reports different licences for the latest release.
Reports and `update` use the same evidence and
[checksum-keyed cache](/docs/#caching).

```sh
licence_audit check
licence_audit check --checks=vulns
licence_audit check --checks=all
```

| Selection | Licence policy | Network requests |
|---|---|---|
| `licences` (default) | Requires a non-empty `allow` list | Licence metadata only |
| `vulns` | No licence enforcement or required `allow` list | OSV only |
| `all` | Requires a non-empty `allow` list | Licence metadata and OSV |

Adding or removing a licence policy does not change the selected scans.
Vulnerability settings in configuration do not enable a scan.

**Migration:** Replace the removed `check --vulns` flag with
`check --checks=all` to keep the previous combined gate. Use
`check --checks=vulns` for a vulnerability-only gate. Standalone `vulns`
remains report-only, and `sbom --vulns` still embeds advisories.

## Define a policy

See [configuration discovery](/docs/configuration#discovery) for how the
command selects the policy file and handles explicit `--config` files.

Add the policy to `[tools.licence_audit]` in `gleam.toml`:

```toml
[tools.licence_audit]
allow = ["Apache-2.0", "MIT"]
deny  = ["GPL-3.0-only"]
```

An `allow` list permits only the specified licences. A `deny` list rejects
matching licences. To create the policy, use
[`licence_audit update`](/docs/update). The command gets metadata, selects existing entries,
asks you to confirm the selection, and writes the result. It preserves
comments in `gleam.toml`.

### Configuration validation

Unknown keys in `[tools.licence_audit]` or its `notices` table are errors with
exit code `2`. The policy keys are `allow`, `deny`, `vuln_severity`,
`vuln_block_unknown`, `exceptions`, and `notices`; the notices keys are `include`
and `exclude`. The error names the unknown key. An older binary therefore
rejects keys added by a newer release instead of silently ignoring them.

Every configured `allow` and `deny` entry must parse as an SPDX
expression. Empty entries and malformed expressions such as `MIT/Apache-2.0`
or `Apache 2.0` cause exit code `2`. Validation checks syntax, not membership in
the SPDX License List. Custom identifiers and `LicenseRef-`/`DocumentRef-`
forms remain supported. Validation does not change the entry text.

### 1.0 allow-list requirement

For version 1.0, `check --checks=licences` (the default) and
`check --checks=all` require a non-empty `allow` list. A deny-only policy
returns exit code `2` and asks you to add `allow`. This requirement replaces
deny-only licence checks supported by earlier releases.
`check --checks=vulns` does not require or enforce a licence policy.

`deny` is an exact-match override and wins over `allow`. Matching does not
normalise deprecated identifiers, a trailing `+`, `-or-later` identifiers, or
`WITH` terms into equivalent licences. List the complete identifiers or terms
that you intend to allow or deny.

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

Each separate string in a package's licence list must pass. A full
expression in `allow` accepts its terms. It does not override a `deny` rule on
one of its operands. A full expression in `deny` rejects that declaration.
Expression matching ignores whitespace between tokens and the case of SPDX
identifiers. It keeps the case of custom references and the tokens of the
expression.

Malformed expressions fail licence evaluation.
For untrusted metadata, the parser limits each expression to 64 KiB,
1024 tokens, and 64 nested parentheses. Expressions above these limits fail
the gate.

## Select an alternate policy

Use `--config` to select a different policy file:

```sh
licence_audit check --config=policies/release.toml
```

For licence-only or combined checks, the file must have a
`[tools.licence_audit]` section with a non-empty `allow` list.
Vulnerability-only checks accept a valid file without this section.
Both flows validate supplied settings, including exceptions.
The selected file supplies the lists and exceptions without adding rules
from the default configuration. Edit TOML or run `update` to change policy.

The default report and [`report`](/docs/report) preview the selected policy and return
exit code `0` for findings when the scan completes. Use `--ignore-config`
for a report without policy evaluation. Licence-only and combined checks with
`--ignore-config` return exit code `2` because they have no licence policy to
enforce. Vulnerability-only checks can use `--ignore-config` with CLI settings.

## Exit codes

Completed licence checks exit `0` when the policy passes and `1` for policy
violations. Unavailable or invalid package metadata exits `2`, even when a
partial report is available or other packages violate the policy. The
`report` command also exits `2` for these metadata failures.

Required evidence includes a valid `outer_checksum` and the locked archive's
`metadata.config`. A checksum mismatch, failed download, or invalid or missing
metadata cannot fall back to API licences. Create a checksum-bearing lockfile
with `gleam deps download`.

## Production-only gates

Use `--prod-only` when your gate should consider only production dependencies.
The command then ignores licence violations in development dependencies. This
option prevents tooling-only packages from causing a CI failure.

Production dependencies are the packages reachable from `[dependencies]` in
the `gleam.toml` beside the selected manifest. A valid file without that table,
or with an empty table, has no production dependencies. This rule also applies
to `check --checks=all --prod-only` and `check --checks=vulns --prod-only`.

A missing `gleam.toml` uses all lockfile direct dependencies as production
roots. An unreadable file, invalid TOML, or a `dependencies` value that is not a
table causes exit code `2`. `--ignore-config` skips policy settings, not this
scope validation.

## Also fail on vulnerabilities

Select `--checks=all` to run the licence audit and query OSV.dev. The command fails
when an advisory meets or exceeds the severity threshold:

```sh
licence_audit check --checks=all
licence_audit check --checks=all --vuln-severity=medium
licence_audit check --checks=all --vuln-block-unknown
```

Use `--checks=vulns` with the same gate flags to query OSV without licence
metadata requests or licence enforcement, even with a configured licence policy:

```sh
licence_audit check --checks=vulns --vuln-severity=medium
```

The threshold is `low` \| `medium` \| `high` (default) \| `critical`.
Advisories with severity `none` (a valid CVSS score of `0.0`) never cause a
failure, even with `--vuln-block-unknown`. `none` is not a gate threshold.
The command reports advisories with unknown severity. By default, these
advisories do not cause a failure. Use `--vuln-block-unknown` to make these
advisories cause a failure. OSV batch or advisory-detail failures exit `2`,
because the gate cannot complete. You can set the threshold in the configuration:

```toml
[tools.licence_audit]
vuln_severity = "high"
vuln_block_unknown = true
```

The CLI flags `--vuln-severity` and `--vuln-block-unknown` require
`--checks=vulns` or `--checks=all`.
With licence-only selection, they cause a usage error (exit 1), including an explicit
`--vuln-block-unknown=false`. They do not enable a scan. The configuration keys
remain valid with any selection and apply only to selected vulnerability gates.

`--vuln-severity` overrides the configured threshold. `--vuln-block-unknown`
can only enable blocking: if you omit it, a configured `true` still applies.
There is no CLI flag to turn this setting off. Select an alternate policy with
`--config` to use a different value while retaining the required licence rules.

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
declared expression. Licence selectors use the same token matching as `allow`
and `deny`: ordinary SPDX identifier case and whitespace between tokens do not
affect the match. For example, `gpl-3.0-only` matches `GPL-3.0-only`.
Custom `LicenseRef-` and `DocumentRef-` references remain case-sensitive.
Parentheses and licence variants remain distinct.

A denied term takes precedence over an unallowed term.
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
including licence selectors that differ only in ordinary identifier case or
token whitespace, and entries that overlap through advisory aliases. Remove
one entry instead of relying on file order.

### Precedence and expiry

The command evaluates global rules first, then applies each matching
exception. An active exception can accept an explicit configured deny.
It does not modify the global lists or declared metadata.
Exceptions alone do not replace the licence policy required by
licence-only or combined checks. Vulnerability-only checks use advisory
exceptions and report licence exceptions as `not evaluated`.
`--ignore-config` ignores the exceptions along with other settings.

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
[`report`](/docs/report) previews licence exceptions without enforcing them, and
[`vulns`](/docs/vulns) displays advisory exceptions without enforcing a gate.

Exceptions cannot accept failed network requests, malformed metadata, missing
advisory details, or unsupported source coverage. They do not change SBOM
evidence, remove notice content, or remove licence-text and attribution
requirements. `update` preserves exception entries and their comments.

## Flags

<!-- cli-reference -->
Enforce selected checks: licences (default), vulns, or all. Licence checks require a licence policy. Vulnerability-only checks do not evaluate licence policy or fetch licence metadata.

**Usage:**

```
licence_audit check [--flags]
```

**Flags:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `--cache-path` | `STRING` |  | Override the licence metadata cache directory |
| `--checks` | `STRING` | `licences` | Select checks: licences\|vulns\|all (default licences); licences and all require a licence policy |
| `--color` | `STRING` | `auto` | Colorize output: auto\|always\|never (default auto; alias: --colour) |
| `--config` | `STRING` |  | Read configuration from PATH |
| `--ignore-config` | `BOOL` | `false` | Ignore configuration files |
| `--manifest` | `STRING` |  | Read manifest from PATH |
| `--no-cache` | `BOOL` | `false` | Bypass the on-disk caches |
| `--prod-only` | `BOOL` | `false` | Only scan production dependencies; exclude dev dependencies |
| `--quiet` | `BOOL` | `false` | Suppress progress output (alias: -q) |
| `--verbose` | `BOOL` | `false` | Show detailed progress output (alias: -v) |
| `--vuln-block-unknown` | `BOOL` |  | Fail on advisories whose severity is unknown (default false; requires --checks=vulns or --checks=all) |
| `--vuln-severity` | `STRING` |  | Minimum blocking vulnerability severity: low\|medium\|high\|critical (default high; requires --checks=vulns or --checks=all) |
<!-- cli-referencestop -->
