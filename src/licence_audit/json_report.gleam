import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import licence_audit/error
import licence_audit/exception
import licence_audit/manifest
import licence_audit/osv
import licence_audit/policy
import licence_audit/report

pub type Command {
  Report
  Check
  Vulns
}

pub type CheckKind {
  Licences
  Vulnerabilities
}

/// A failed gate can also be incomplete. Completeness is stored separately.
pub type GateVerdict {
  NotEnforced
  Passed
  Failed
  Undetermined
}

pub type SkippedSource {
  SkippedSource(package: String, source: String)
}

/// Supply counts from the full in-scope report, not a filtered display tree.
pub type LicenceResult {
  LicenceResult(
    rows: List(report.Row),
    counts: report.Counts,
    skipped_sources: List(SkippedSource),
    coverage: exception.Coverage,
    complete: Bool,
  )
}

/// `blocking` is absent when the gate has not evaluated this occurrence.
/// Unavailable details are not a fetched advisory with unknown severity.
pub type AdvisoryResult {
  Available(
    advisory: osv.Vulnerability,
    decision: exception.Decision,
    blocking: Option(Bool),
  )
  Unavailable(advisory_id: String, failure: error.Error)
}

pub type VulnerabilityRow {
  VulnerabilityRow(
    package: String,
    version: String,
    purl: String,
    result: AdvisoryResult,
  )
}

pub type VulnerabilityResult {
  VulnerabilityResult(
    rows: List(VulnerabilityRow),
    queried_packages: Int,
    skipped_sources: List(SkippedSource),
    coverage: exception.Coverage,
    complete: Bool,
  )
}

/// Absent results mean the check did not start, not a complete empty scan.
/// The caller supplies the final exit outcome independently of gate findings.
pub type Document {
  Document(
    command: Command,
    checks_requested: List(CheckKind),
    licences: Option(LicenceResult),
    vulnerabilities: Option(VulnerabilityResult),
    exceptions: List(exception.Exception),
    today: String,
    gate_verdict: GateVerdict,
    complete: Bool,
    outcome: error.Error,
  )
}

/// Encode one schema-1 document without printing, logging, or performing I/O.
pub fn to_string(document: Document) -> String {
  let licence_coverage = case document.licences {
    None -> exception.NotEvaluated("licence check did not run")
    Some(result) -> result.coverage
  }
  let vulnerability_coverage = case document.vulnerabilities {
    None -> exception.NotEvaluated("vulnerability check did not run")
    Some(result) -> result.coverage
  }
  json.object([
    #("schema_version", json.int(1)),
    #("command", json.string(command_name(document.command))),
    #("exit_code", json.int(error.exit_code(document.outcome))),
    #("complete", json.bool(document.complete)),
    #("licences", optional(document.licences, licence_result_to_json)),
    #(
      "vulnerabilities",
      optional(document.vulnerabilities, vulnerability_result_to_json),
    ),
    #(
      "summary",
      json.object([
        #(
          "checks_requested",
          json.array(list.unique(document.checks_requested), check_to_json),
        ),
        #("checks_run", json.array(checks_run(document), check_to_json)),
        #("gate_verdict", json.string(verdict_name(document.gate_verdict))),
        #(
          "counts",
          json.object([
            #(
              "licences",
              optional(document.licences, fn(result) {
                licence_counts_to_json(result.counts)
              }),
            ),
            #(
              "vulnerabilities",
              optional(document.vulnerabilities, vulnerability_counts_to_json),
            ),
          ]),
        ),
        #(
          "skipped_sources",
          json.object([
            #(
              "licences",
              optional(document.licences, fn(result) {
                json.array(result.skipped_sources, skipped_to_json)
              }),
            ),
            #(
              "vulnerabilities",
              optional(document.vulnerabilities, fn(result) {
                json.array(result.skipped_sources, skipped_to_json)
              }),
            ),
          ]),
        ),
        #(
          "exception_coverage",
          json.object([
            #("licences", coverage_to_json(licence_coverage)),
            #("vulnerabilities", coverage_to_json(vulnerability_coverage)),
            #(
              "entries",
              json.array(document.exceptions, fn(entry) {
                exception_coverage_to_json(
                  entry,
                  document.today,
                  licence_coverage,
                  vulnerability_coverage,
                )
              }),
            ),
          ]),
        ),
      ]),
    ),
    #("errors", case document.outcome {
      error.Success -> json.array([], failure_to_json)
      failure -> json.array([failure], failure_to_json)
    }),
  ])
  |> json.to_string
}

fn command_name(command: Command) -> String {
  case command {
    Report -> "report"
    Check -> "check"
    Vulns -> "vulns"
  }
}

fn check_to_json(check: CheckKind) -> json.Json {
  json.string(case check {
    Licences -> "licences"
    Vulnerabilities -> "vulns"
  })
}

fn checks_run(document: Document) -> List(CheckKind) {
  let licences = case document.licences {
    None -> []
    Some(_) -> [Licences]
  }
  let vulnerabilities = case document.vulnerabilities {
    None -> []
    Some(_) -> [Vulnerabilities]
  }
  list.append(licences, vulnerabilities)
}

fn verdict_name(verdict: GateVerdict) -> String {
  case verdict {
    NotEnforced -> "not_enforced"
    Passed -> "passed"
    Failed -> "failed"
    Undetermined -> "undetermined"
  }
}

fn optional(value: Option(a), encode: fn(a) -> json.Json) -> json.Json {
  case value {
    None -> json.null()
    Some(value) -> encode(value)
  }
}

fn licence_result_to_json(result: LicenceResult) -> json.Json {
  json.object([
    #("complete", json.bool(result.complete)),
    #("rows", json.array(result.rows, licence_row_to_json)),
  ])
}

fn licence_counts_to_json(counts: report.Counts) -> json.Json {
  json.object([
    #("total", json.int(counts.total)),
    #("allowed", json.int(counts.allowed)),
    #("denied", json.int(counts.denied)),
    #("unknown", json.int(counts.unknown)),
    #("excepted", json.int(counts.excepted)),
    #("skipped", json.int(counts.skipped)),
  ])
}

fn licence_row_to_json(row: report.Row) -> json.Json {
  let #(status, findings, failure, source) = case row.status {
    report.NotChecked -> #("not_checked", [], json.null(), json.null())
    report.Checked(policy.Allowed) -> #("allowed", [], json.null(), json.null())
    report.Checked(policy.DeniedLicence(value)) -> #(
      "denied",
      [#(exception.DeniedLicence(value), exception.Unaccepted)],
      json.null(),
      json.null(),
    )
    report.Checked(policy.UnallowedLicence(value)) -> #(
      "unallowed",
      [#(exception.UnallowedLicence(value), exception.Unaccepted)],
      json.null(),
      json.null(),
    )
    report.Checked(policy.InvalidLicenceExpression(value)) -> #(
      "invalid_licence_expression",
      [#(exception.InvalidLicenceExpression(value), exception.Unaccepted)],
      json.null(),
      json.null(),
    )
    report.Checked(policy.NoLicencesDeclared) -> #(
      "no_licences_declared",
      [#(exception.NoLicencesDeclared, exception.Unaccepted)],
      json.null(),
      json.null(),
    )
    report.Reviewed(findings) -> #(
      "reviewed",
      findings,
      json.null(),
      json.null(),
    )
    report.Failed(message) -> #(
      "failed",
      [],
      json.object([
        #("code", json.string("metadata_unavailable")),
        #("message", json.string(message)),
      ]),
      json.null(),
    )
    report.Skipped(source) -> #("skipped", [], json.null(), json.string(source))
  }
  json.object([
    #("package", json.string(row.package)),
    #("version", json.string(row.version)),
    #(
      "scope",
      json.string(case row.scope {
        manifest.Prod -> "prod"
        manifest.Dev -> "dev"
      }),
    ),
    #("licences", json.array(row.licences, json.string)),
    #("status", json.string(status)),
    #(
      "findings",
      json.array(findings, fn(finding) {
        json.object([
          #("finding", finding_to_json(finding.0)),
          #("exception_decision", decision_to_json(finding.1)),
        ])
      }),
    ),
    #("dependency_path", json.array(row.path, json.string)),
    #("error", failure),
    #("source", source),
  ])
}

fn finding_to_json(finding: exception.Finding) -> json.Json {
  let #(kind, value) = case finding {
    exception.DeniedLicence(value) -> #("denied_licence", json.string(value))
    exception.UnallowedLicence(value) -> #(
      "unallowed_licence",
      json.string(value),
    )
    exception.InvalidLicenceExpression(value) -> #(
      "invalid_licence_expression",
      json.string(value),
    )
    exception.NoLicencesDeclared -> #("no_licences_declared", json.null())
    exception.Advisory(value) -> #("advisory", json.string(value))
  }
  json.object([#("kind", json.string(kind)), #("value", value)])
}

fn decision_to_json(decision: exception.Decision) -> json.Json {
  let #(status, entry) = case decision {
    exception.Unaccepted -> #("unaccepted", None)
    exception.Excepted(entry) -> #("excepted", Some(entry))
    exception.Expired(entry) -> #("expired", Some(entry))
  }
  json.object([
    #("status", json.string(status)),
    #("exception", optional(entry, exception_to_json)),
  ])
}

fn exception_to_json(entry: exception.Exception) -> json.Json {
  json.object([
    #("number", json.int(entry.number)),
    #("purl", json.string(entry.purl)),
    #("finding", finding_to_json(entry.finding)),
    #("reason", json.string(entry.reason)),
    #("expires", optional(entry.expires, json.string)),
  ])
}

fn vulnerability_result_to_json(result: VulnerabilityResult) -> json.Json {
  json.object([
    #("complete", json.bool(result.complete)),
    #("rows", json.array(result.rows, vulnerability_row_to_json)),
  ])
}

fn vulnerability_counts_to_json(result: VulnerabilityResult) -> json.Json {
  let available =
    list.filter_map(result.rows, fn(row) {
      case row.result {
        Available(_, decision, blocking) -> Ok(#(decision, blocking))
        Unavailable(_, _) -> Error(Nil)
      }
    })
  json.object([
    #("queried_packages", json.int(result.queried_packages)),
    #("occurrences", json.int(list.length(result.rows))),
    #(
      "blocking",
      json.int(
        available
        |> list.filter(fn(row) { row.1 == Some(True) })
        |> list.length,
      ),
    ),
    #(
      "excepted",
      json.int(
        available
        |> list.filter(fn(row) { exception.accepted(row.0) })
        |> list.length,
      ),
    ),
    #(
      "unavailable",
      json.int(list.length(result.rows) - list.length(available)),
    ),
  ])
}

fn vulnerability_row_to_json(row: VulnerabilityRow) -> json.Json {
  let #(id, aliases, severity, blocking, decision, failure) = case row.result {
    Available(advisory, decision, blocking) -> #(
      advisory.id,
      json.array(advisory.aliases, json.string),
      json.string(osv.severity_to_string(advisory.severity)),
      optional(blocking, json.bool),
      decision_to_json(decision),
      json.null(),
    )
    Unavailable(id, failure) -> #(
      id,
      json.null(),
      json.null(),
      json.null(),
      json.null(),
      failure_to_json(failure),
    )
  }
  json.object([
    #("package", json.string(row.package)),
    #("version", json.string(row.version)),
    #("purl", json.string(row.purl)),
    #("advisory_id", json.string(id)),
    #("aliases", aliases),
    #("severity", severity),
    #("blocking", blocking),
    #("exception_decision", decision),
    #("error", failure),
  ])
}

fn skipped_to_json(skipped: SkippedSource) -> json.Json {
  json.object([
    #("package", json.string(skipped.package)),
    #("source", json.string(skipped.source)),
  ])
}

fn coverage_to_json(coverage: exception.Coverage) -> json.Json {
  let #(evaluated, reason, matched, unavailable) = case coverage {
    exception.NotEvaluated(reason) -> #(False, Some(reason), [], [])
    exception.Evaluated(matched, unavailable) -> #(
      True,
      None,
      list.unique(matched),
      unavailable,
    )
  }
  json.object([
    #("evaluated", json.bool(evaluated)),
    #("reason", optional(reason, json.string)),
    #("matched", json.array(matched, json.int)),
    #(
      "unavailable",
      json.array(unavailable, fn(entry) {
        json.object([
          #("purl", json.string(entry.0)),
          #("reason", json.string(entry.1)),
        ])
      }),
    ),
  ])
}

fn exception_coverage_to_json(
  entry: exception.Exception,
  today: String,
  licences: exception.Coverage,
  vulnerabilities: exception.Coverage,
) -> json.Json {
  let coverage = case entry.finding {
    exception.Advisory(_) -> vulnerabilities
    exception.DeniedLicence(_)
    | exception.UnallowedLicence(_)
    | exception.InvalidLicenceExpression(_)
    | exception.NoLicencesDeclared -> licences
  }
  let #(status, reason) = case coverage {
    exception.NotEvaluated(reason) -> #("not_evaluated", Some(reason))
    exception.Evaluated(matched, unavailable) ->
      case list.contains(matched, entry.number) {
        True -> #("matched", None)
        False ->
          case list.key_find(unavailable, entry.purl) {
            Ok(reason) -> #("not_evaluated", Some(reason))
            Error(_) -> #("unused", None)
          }
      }
  }
  json.object([
    #("exception", exception_to_json(entry)),
    #("status", json.string(status)),
    #("reason", optional(reason, json.string)),
    #("expired", json.bool(exception.is_expired(entry, today))),
  ])
}

fn failure_to_json(failure: error.Error) -> json.Json {
  let code = case failure {
    error.Success -> "success"
    error.AuditFailed -> "audit_failed"
    error.MissingPolicy -> "missing_policy"
    error.Usage(_) -> "usage"
    error.RuntimeStartup(_) -> "runtime_startup"
    error.RuntimeException(_) -> "runtime_exception"
    error.Config(_) -> "config"
    error.Input(_) -> "input"
    error.Hex(_) -> "hex"
    error.Decode(_) -> "decode"
    error.UnsupportedSourceForSbom(_, _, _) -> "unsupported_source_for_sbom"
    error.SbomMetadataFailed(_, _) -> "sbom_metadata_failed"
    error.SbomPublicationFailed(_, _) -> "sbom_publication_failed"
    error.SbomSerialNumberFailed -> "sbom_serial_number_failed"
    error.SbomWriteFailed(_, _) -> "sbom_write_failed"
    error.Osv(_) -> "osv"
    error.Notices(_) -> "notices"
  }
  json.object([
    #("code", json.string(code)),
    #("message", json.string(error.message(failure))),
  ])
}
