---
layout: ../../layouts/DocsLayout.astro
title: JSON reports
description: Schema 1 for licence and vulnerability reports, gate results, and partial failures.
---

Select JSON on the named `report`, `check`, or `vulns` command:

```sh
licence_audit report --format=json
licence_audit check --checks=all --format json
licence_audit vulns --format=json
```

Text remains the default. Bare invocation does not accept `--format`.
`--help` always returns ordinary help text. The report schema is separate
from the CycloneDX format used by `sbom`.

## Compatibility

Consumers must ignore unknown object fields. Within schema 1, maintainers
preserve the field names, types, nullability, required fields, and meanings
listed below. Object field order and whitespace have no compatibility promise.
The value sets listed below are closed.

Maintainers must use a new schema version for incompatible changes. Within a
major CLI version, maintainers must preserve the old schema and the default
schema, and require consumers to opt in to an incompatible schema.

## Document

Each JSON invocation writes one schema-1 JSON object to stdout, including
recognized usage errors and input, configuration, network, and runtime failures.
Progress and logs use stderr. Exit codes remain `0`, `1`, and `2`.
Use both the exit code and completeness fields; a gate can fail while some
evidence remains unavailable.

All fields in this document are required. A nullable field uses JSON `null`;
the serializer does not omit it.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | `1`. |
| `command` | string | `report`, `check`, or `vulns`. |
| `exit_code` | integer | Existing command exit category: `0`, `1`, or `2`. |
| `complete` | boolean | Whether the command completed its requested work. |
| `licences` | result object or null | Available licence results; null means the licence check did not start. |
| `vulnerabilities` | result object or null | Available vulnerability results; null means the vulnerability check did not start. |
| `summary` | object | Counts, check selection, gate verdict, skipped sources, and exception coverage. |
| `errors` | array of error objects | The final command failure, or an empty array for exit `0`. |

Each result object has `complete` (boolean) and `rows` (array). An incomplete
result retains available rows. A complete result with an
empty row array represents a completed scan with no rows.

Gate verdict, completion, and exit outcome are separate values.
A document can contain blocking findings, `gate_verdict: "failed"`,
`complete: false`, and exit code `2`. Consumers must examine both the findings
and completion fields. A report-only invocation can return exit `0` while
retaining errors for optional advisory details in its rows.

## Licence rows

| Field | Type | Meaning |
| --- | --- | --- |
| `package`, `version` | string | Locked package identity. |
| `scope` | string | `prod` or `dev`. |
| `licences` | array of strings | Licence declarations from package metadata. |
| `status` | string | `not_checked`, `allowed`, `denied`, `unallowed`, `invalid_licence_expression`, `no_licences_declared`, `reviewed`, `failed`, or `skipped`. |
| `findings` | array of objects | Each object has `finding` and `exception_decision`. |
| `dependency_path` | array of strings | Root-to-package path, including non-Hex intermediate packages. |
| `error` | error object or null | Metadata failure with code `metadata_unavailable`; null for other states. |
| `source` | string or null | Dependency source for a skipped row; null for other states. |

A `reviewed` row can contain both accepted and unaccepted findings. Consumers
must inspect each decision. An empty `findings` array on a `failed` or
`not_checked` row does not establish compliance.

Each finding object has `kind` (string) and `value` (string or null). Kinds
are `denied_licence`, `unallowed_licence`, `invalid_licence_expression`,
`no_licences_declared`, and `advisory`. The value preserves the licence
expression or advisory ID. `no_licences_declared` uses null.

Each decision object has `status` and `exception`. Status is `unaccepted`,
`excepted`, or `expired`. The exception is null for `unaccepted`; the other
states include the matched exception object.

An exception object has `number` (integer), `purl` (string), `finding`
(finding object), `reason` (string), and `expires` (string or null).
`number` identifies the configured exception entry. `expires` is a UTC
`YYYY-MM-DD` date; null means no expiry.

## Vulnerability rows

| Field | Type | Meaning |
| --- | --- | --- |
| `package`, `version`, `purl` | string | Locked package identity and resolved vulnerability-query purl. |
| `advisory_id` | string | Advisory ID, including when detail lookup fails. |
| `aliases` | array of strings or null | Fetched advisory aliases; null for unavailable details. |
| `severity` | string or null | `none`, `low`, `medium`, `high`, `critical`, or `unknown`; null for unavailable details. |
| `blocking` | boolean or null | The gate's decision after exception handling; null when the gate has not evaluated this occurrence. |
| `exception_decision` | decision object or null | The reviewed exception decision; null for unavailable details or an incomplete exception review. |
| `error` | error object or null | Detail-lookup or exception-review failure; null after a completed review. |

Each row represents one package/advisory occurrence. The same advisory can
appear for several packages. Consumers must distinguish a fetched advisory
with severity `unknown` from an advisory with unavailable details.
If exception review fails, the serializer retains fetched severity and aliases,
uses null for the decision and blocking fields, and records the review error.

## Summary

`checks_requested` and `checks_run` are arrays containing `licences` or
`vulns`. Requested checks follow the command and `--checks` selection.
A check is listed as run when its result object is present, including incomplete
results. A configuration error can leave requested checks with no run results.

`gate_verdict` is `not_enforced`, `passed`, `failed`, or `undetermined`.
`failed` records a known gate failure even if another part of the command
remains incomplete. `undetermined` means an enforced gate lacks a verdict.

`counts` has `licences` and `vulnerabilities`, each nullable:

- Licence counts have integer `total`, `allowed`, `denied`, `unknown`,
  `excepted`, and `skipped` fields. Counts come from the
  full in-scope report, before any display filtering.
- Vulnerability counts have integer `queried_packages`, `occurrences`,
  `blocking`, `excepted`, and `unavailable` fields. The queried package count
  records packages in the completed OSV batch response. Occurrences count the
  rows, including unavailable details. `blocking` counts known blocking
  occurrences; `excepted` counts occurrences with accepted exceptions.

`skipped_sources` has nullable `licences` and `vulnerabilities` arrays. Each
entry has string `package` and `source` fields. Null means the check did not
start; an empty array means the caller reported no skipped sources.

`exception_coverage` has `licences`, `vulnerabilities`, and `entries`.
Each check's coverage object has boolean `evaluated`, nullable string `reason`,
integer array `matched`, and array `unavailable`. Each unavailable entry has
string `purl` and `reason` fields. `matched` includes expired matches.
`evaluated: true` can coexist with unavailable package identities.

Each configured exception entry in `entries` has `exception` (exception
object), `status` (`matched`, `unused`, or `not_evaluated`), `reason`
(string or null), and `expired` (boolean). A matched entry takes precedence
over unavailable coverage for the same purl. Consumers must inspect expiry
as well as coverage; a matched expired exception does not accept a finding.

## Errors

Each error object has string `code` and `message` fields. Consumers should
use codes and exit categories for decisions. Maintainers can change message
wording.

Command error codes are `audit_failed`, `missing_policy`, `usage`,
`runtime_startup`, `runtime_exception`, `config`, `input`, `hex`, `decode`,
`osv`, and `notices`. The shared encoder also recognizes
`unsupported_source_for_sbom`, `sbom_metadata_failed`,
`sbom_publication_failed`, `sbom_serial_number_failed`, and `sbom_write_failed`
from the existing error domain. A successful command has no command error.

The serializer retains per-row errors alongside the final command error.
An empty error array does not establish a passing gate. Operational failure
does not remove available findings.
