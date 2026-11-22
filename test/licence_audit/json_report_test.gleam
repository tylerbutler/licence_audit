import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleeunit/should
import licence_audit/error
import licence_audit/exception
import licence_audit/json_report
import licence_audit/manifest
import licence_audit/osv
import licence_audit/policy
import licence_audit/report

fn document() -> json_report.Document {
  json_report.Document(
    command: json_report.Report,
    checks_requested: [json_report.Licences],
    licences: None,
    vulnerabilities: None,
    exceptions: [],
    today: "2026-11-21",
    gate_verdict: json_report.NotEnforced,
    complete: False,
    outcome: error.Success,
  )
}

fn read(document: json_report.Document, decoder: decode.Decoder(a)) -> a {
  let assert Ok(value) = json.parse(json_report.to_string(document), decoder)
  value
}

fn review(number: Int, finding: exception.Finding) -> exception.Exception {
  exception.Exception(
    number: number,
    purl: "pkg:hex/example@1.0.0",
    finding: finding,
    reason: "review \"quoted\"\nnext line",
    expires: Some("2026-11-20"),
  )
}

fn licence_result(rows: List(report.Row)) -> json_report.LicenceResult {
  json_report.LicenceResult(
    rows: rows,
    counts: report.counts(rows, report.Summary([])),
    skipped_sources: [],
    coverage: exception.Evaluated([], []),
    complete: True,
  )
}

fn advisory(severity: osv.Severity) -> osv.Vulnerability {
  osv.Vulnerability(
    id: "GHSA-example",
    aliases: ["CVE-2026-1234"],
    summary: "example",
    severity: severity,
    scores: [],
    affected: [],
  )
}

fn vulnerability_row(
  result: json_report.AdvisoryResult,
) -> json_report.VulnerabilityRow {
  json_report.VulnerabilityRow(
    package: "example",
    version: "1.0.0",
    purl: "pkg:hex/example@1.0.0",
    result: result,
  )
}

pub fn licence_statuses_keep_not_checked_empty_and_skipped_distinct_test() -> Nil {
  let rows =
    list.map(
      [
        report.NotChecked,
        report.Checked(policy.Allowed),
        report.Checked(policy.NoLicencesDeclared),
        report.Checked(policy.DeniedLicence("GPL-3.0-only")),
        report.Checked(policy.UnallowedLicence("LicenseRef-private")),
        report.Checked(policy.InvalidLicenceExpression("MIT AND (")),
        report.Skipped("git"),
      ],
      fn(status) {
        report.Row(
          package: "example",
          version: "1.0.0",
          licences: [],
          status: status,
          scope: manifest.Prod,
          path: ["example"],
        )
      },
    )
  let decoder =
    decode.at(
      ["licences", "rows"],
      decode.list({
        use status <- decode.field("status", decode.string)
        use source <- decode.field("source", decode.optional(decode.string))
        use findings <- decode.field(
          "findings",
          decode.list({
            use kind <- decode.subfield(["finding", "kind"], decode.string)
            use value <- decode.subfield(
              ["finding", "value"],
              decode.optional(decode.string),
            )
            decode.success(#(kind, value))
          }),
        )
        decode.success(#(status, source, findings))
      }),
    )
  should.equal(
    read(
      json_report.Document(..document(), licences: Some(licence_result(rows))),
      decoder,
    ),
    [
      #("not_checked", None, []),
      #("allowed", None, []),
      #("no_licences_declared", None, [#("no_licences_declared", None)]),
      #("denied", None, [#("denied_licence", Some("GPL-3.0-only"))]),
      #("unallowed", None, [#("unallowed_licence", Some("LicenseRef-private"))]),
      #("invalid_licence_expression", None, [
        #("invalid_licence_expression", Some("MIT AND (")),
      ]),
      #("skipped", Some("git"), []),
    ],
  )
}

pub fn reviewed_licences_preserve_each_finding_and_decision_test() -> Nil {
  let invalid = exception.InvalidLicenceExpression("MIT AND (")
  let expired = review(7, invalid)
  let row =
    report.Row(
      package: "example",
      version: "1.0.0",
      licences: ["MIT AND (", "GPL-3.0-only"],
      status: report.Reviewed([
        #(invalid, exception.Expired(expired)),
        #(exception.DeniedLicence("GPL-3.0-only"), exception.Unaccepted),
      ]),
      scope: manifest.Dev,
      path: ["root", "git_parent", "example"],
    )
  let document =
    json_report.Document(
      ..document(),
      licences: Some(licence_result([row])),
      complete: True,
      outcome: error.AuditFailed,
      gate_verdict: json_report.Failed,
    )
  let decoder = {
    use rows <- decode.subfield(
      ["licences", "rows"],
      decode.list({
        use scope <- decode.field("scope", decode.string)
        use path <- decode.field("dependency_path", decode.list(decode.string))
        use findings <- decode.field(
          "findings",
          decode.list({
            use kind <- decode.subfield(["finding", "kind"], decode.string)
            use value <- decode.subfield(["finding", "value"], decode.string)
            use decision <- decode.subfield(
              ["exception_decision", "status"],
              decode.string,
            )
            use reason <- decode.subfield(
              ["exception_decision", "exception"],
              decode.optional(decode.at(["reason"], decode.string)),
            )
            decode.success(#(kind, value, decision, reason))
          }),
        )
        decode.success(#(scope, path, findings))
      }),
    )
    use denied <- decode.subfield(
      ["summary", "counts", "licences", "denied"],
      decode.int,
    )
    decode.success(#(rows, denied))
  }
  should.equal(read(document, decoder), #(
    [
      #("dev", ["root", "git_parent", "example"], [
        #(
          "invalid_licence_expression",
          "MIT AND (",
          "expired",
          Some(expired.reason),
        ),
        #("denied_licence", "GPL-3.0-only", "unaccepted", None),
      ]),
    ],
    1,
  ))
}

pub fn combined_partial_results_keep_blocking_findings_and_errors_test() -> Nil {
  let vulnerability_result =
    json_report.VulnerabilityResult(
      rows: [
        vulnerability_row(json_report.Available(
          advisory(osv.Critical),
          exception.Unaccepted,
          Some(True),
        )),
        vulnerability_row(json_report.Unavailable(
          "GHSA-unavailable",
          error.Osv("connection failed"),
        )),
      ],
      queried_packages: 1,
      skipped_sources: [json_report.SkippedSource("local", "path")],
      coverage: exception.Evaluated([], [
        #("pkg:hex/example@1.0.0", "advisory details unavailable"),
      ]),
      complete: False,
    )
  let document =
    json_report.Document(
      ..document(),
      command: json_report.Check,
      checks_requested: [json_report.Licences, json_report.Vulnerabilities],
      licences: Some(licence_result([])),
      vulnerabilities: Some(vulnerability_result),
      gate_verdict: json_report.Failed,
      outcome: error.Osv("advisory details unavailable"),
    )
  let decoder = {
    use exit <- decode.field("exit_code", decode.int)
    use complete <- decode.field("complete", decode.bool)
    use checks <- decode.subfield(
      ["summary", "checks_run"],
      decode.list(decode.string),
    )
    use verdict <- decode.subfield(["summary", "gate_verdict"], decode.string)
    use blocking <- decode.subfield(
      ["summary", "counts", "vulnerabilities", "blocking"],
      decode.int,
    )
    use unavailable <- decode.subfield(
      ["summary", "counts", "vulnerabilities", "unavailable"],
      decode.int,
    )
    use rows <- decode.subfield(
      ["vulnerabilities", "rows"],
      decode.list({
        use id <- decode.field("advisory_id", decode.string)
        use severity <- decode.field("severity", decode.optional(decode.string))
        use blocking <- decode.field("blocking", decode.optional(decode.bool))
        use failure <- decode.field(
          "error",
          decode.optional(decode.at(["code"], decode.string)),
        )
        decode.success(#(id, severity, blocking, failure))
      }),
    )
    use errors <- decode.field(
      "errors",
      decode.list(decode.at(["code"], decode.string)),
    )
    decode.success(#(
      exit,
      complete,
      checks,
      verdict,
      blocking,
      unavailable,
      rows,
      errors,
    ))
  }
  should.equal(
    read(document, decoder),
    #(
      2,
      False,
      ["licences", "vulns"],
      "failed",
      1,
      1,
      [
        #("GHSA-example", Some("critical"), Some(True), None),
        #("GHSA-unavailable", None, None, Some("osv")),
      ],
      ["osv"],
    ),
  )
}

pub fn vulnerability_only_unknown_severity_is_not_unavailable_test() -> Nil {
  let accepted =
    exception.Exception(
      ..review(8, exception.Advisory("GHSA-example")),
      expires: None,
    )
  let result =
    json_report.VulnerabilityResult(
      rows: [
        vulnerability_row(json_report.Available(
          advisory(osv.UnknownSeverity),
          exception.Excepted(accepted),
          None,
        )),
      ],
      queried_packages: 3,
      skipped_sources: [],
      coverage: exception.Evaluated([8], []),
      complete: True,
    )
  let document =
    json_report.Document(
      ..document(),
      command: json_report.Vulns,
      checks_requested: [json_report.Vulnerabilities],
      vulnerabilities: Some(result),
      exceptions: [accepted],
      complete: True,
    )
  let decoder = {
    use _ <- decode.field("licences", decode.optional(decode.string))
    use requested <- decode.subfield(
      ["summary", "checks_requested"],
      decode.list(decode.string),
    )
    use checks <- decode.subfield(
      ["summary", "checks_run"],
      decode.list(decode.string),
    )
    use unavailable <- decode.subfield(
      ["summary", "counts", "vulnerabilities", "unavailable"],
      decode.int,
    )
    use excepted <- decode.subfield(
      ["summary", "counts", "vulnerabilities", "excepted"],
      decode.int,
    )
    use rows <- decode.subfield(
      ["vulnerabilities", "rows"],
      decode.list({
        use purl <- decode.field("purl", decode.string)
        use aliases <- decode.field("aliases", decode.list(decode.string))
        use severity <- decode.field("severity", decode.string)
        use blocking <- decode.field("blocking", decode.optional(decode.bool))
        use decision <- decode.subfield(
          ["exception_decision", "status"],
          decode.string,
        )
        decode.success(#(purl, aliases, severity, blocking, decision))
      }),
    )
    decode.success(#(requested, checks, unavailable, excepted, rows))
  }
  should.equal(
    read(document, decoder),
    #(["vulns"], ["vulns"], 0, 1, [
      #("pkg:hex/example@1.0.0", ["CVE-2026-1234"], "unknown", None, "excepted"),
    ]),
  )
}

pub fn unavailable_licence_metadata_keeps_dependency_context_test() -> Nil {
  let row =
    report.Row(
      package: "example",
      version: "1.0.0",
      licences: [],
      status: report.Failed("timeout\n\"retry\""),
      scope: manifest.Prod,
      path: ["example"],
    )
  let result =
    json_report.LicenceResult(..licence_result([row]), complete: False)
  let decoder =
    decode.at(
      ["licences", "rows"],
      decode.list({
        use package <- decode.field("package", decode.string)
        use status <- decode.field("status", decode.string)
        use message <- decode.subfield(["error", "message"], decode.string)
        use findings <- decode.field("findings", decode.list(decode.string))
        decode.success(#(package, status, message, findings))
      }),
    )
  should.equal(
    read(json_report.Document(..document(), licences: Some(result)), decoder),
    [#("example", "failed", "timeout\n\"retry\"", [])],
  )
}

pub fn structured_failures_keep_existing_exit_categories_and_no_results_test() -> Nil {
  use entry <- list.each([
    #(error.Config("invalid \"allow\"\nfield"), 2, "config"),
    #(error.Usage("unknown option"), 2, "usage"),
    #(error.Hex("connection failed"), 2, "hex"),
    #(error.AuditFailed, 1, "audit_failed"),
  ])
  let decoder = {
    use version <- decode.field("schema_version", decode.int)
    use exit <- decode.field("exit_code", decode.int)
    use licences <- decode.field("licences", decode.optional(decode.string))
    use vulnerabilities <- decode.field(
      "vulnerabilities",
      decode.optional(decode.string),
    )
    use checks <- decode.subfield(
      ["summary", "checks_run"],
      decode.list(decode.string),
    )
    use errors <- decode.field(
      "errors",
      decode.list({
        use code <- decode.field("code", decode.string)
        use message <- decode.field("message", decode.string)
        decode.success(#(code, message))
      }),
    )
    decode.success(#(version, exit, licences, vulnerabilities, checks, errors))
  }
  should.equal(
    read(json_report.Document(..document(), outcome: entry.0), decoder),
    #(1, entry.1, None, None, [], [#(entry.2, error.message(entry.0))]),
  )
}

pub fn exception_coverage_keeps_matched_unused_and_unavailable_distinct_test() -> Nil {
  let matched = review(1, exception.InvalidLicenceExpression("MIT AND ("))
  let unused = review(2, exception.NoLicencesDeclared)
  let unavailable = review(3, exception.Advisory("GHSA-example"))
  let result =
    json_report.LicenceResult(
      ..licence_result([]),
      coverage: exception.Evaluated([1], []),
    )
  let vulnerability_result =
    json_report.VulnerabilityResult(
      rows: [],
      queried_packages: 1,
      skipped_sources: [],
      coverage: exception.Evaluated([], [
        #("pkg:hex/example@1.0.0", "advisory details unavailable"),
      ]),
      complete: False,
    )
  let decoder =
    decode.at(
      ["summary", "exception_coverage", "entries"],
      decode.list({
        use number <- decode.subfield(["exception", "number"], decode.int)
        use status <- decode.field("status", decode.string)
        use expired <- decode.field("expired", decode.bool)
        use reason <- decode.field("reason", decode.optional(decode.string))
        decode.success(#(number, status, expired, reason))
      }),
    )
  should.equal(
    read(
      json_report.Document(
        ..document(),
        licences: Some(result),
        vulnerabilities: Some(vulnerability_result),
        exceptions: [matched, unused, unavailable],
      ),
      decoder,
    ),
    [
      #(1, "matched", True, None),
      #(2, "unused", True, None),
      #(3, "not_evaluated", True, Some("advisory details unavailable")),
    ],
  )
}

pub fn present_results_keep_full_counts_even_with_no_display_rows_test() -> Nil {
  let result =
    json_report.LicenceResult(
      ..licence_result([]),
      counts: report.Counts(4, 3, 0, 0, 0, 1),
      skipped_sources: [json_report.SkippedSource("local", "path")],
    )
  let decoder = {
    use exit <- decode.field("exit_code", decode.int)
    use complete <- decode.field("complete", decode.bool)
    use rows <- decode.subfield(
      ["licences", "rows"],
      decode.list(decode.string),
    )
    use total <- decode.subfield(
      ["summary", "counts", "licences", "total"],
      decode.int,
    )
    use skipped <- decode.subfield(
      ["summary", "skipped_sources", "licences"],
      decode.list({
        use package <- decode.field("package", decode.string)
        use source <- decode.field("source", decode.string)
        decode.success(#(package, source))
      }),
    )
    use errors <- decode.field("errors", decode.list(decode.string))
    decode.success(#(exit, complete, rows, total, skipped, errors))
  }

  should.equal(
    read(
      json_report.Document(..document(), licences: Some(result), complete: True),
      decoder,
    ),
    #(0, True, [], 4, [#("local", "path")], []),
  )
}

pub fn fetched_but_unreviewed_details_do_not_count_as_unavailable_test() -> Nil {
  let result =
    json_report.VulnerabilityResult(
      rows: [
        vulnerability_row(json_report.Unreviewed(
          advisory(osv.High),
          error.Config("ambiguous advisory exceptions"),
        )),
      ],
      queried_packages: 1,
      skipped_sources: [],
      coverage: exception.NotEvaluated("ambiguous advisory exceptions"),
      complete: False,
    )
  let document =
    json_report.Document(
      ..document(),
      vulnerabilities: Some(result),
      outcome: error.Config("ambiguous advisory exceptions"),
    )
  let decoder = {
    use unavailable <- decode.subfield(
      ["summary", "counts", "vulnerabilities", "unavailable"],
      decode.int,
    )
    use rows <- decode.subfield(
      ["vulnerabilities", "rows"],
      decode.list({
        use aliases <- decode.field("aliases", decode.list(decode.string))
        use severity <- decode.field("severity", decode.string)
        use decision <- decode.field(
          "exception_decision",
          decode.optional(decode.string),
        )
        use blocking <- decode.field("blocking", decode.optional(decode.bool))
        use failure <- decode.subfield(["error", "code"], decode.string)
        decode.success(#(aliases, severity, decision, blocking, failure))
      }),
    )
    decode.success(#(unavailable, rows))
  }
  should.equal(
    read(document, decoder),
    #(0, [#(["CVE-2026-1234"], "high", None, None, "config")]),
  )
}
