import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/hex
import licence_audit/osv
import licence_audit/progress
import licence_audit/source_archive_test
import simplifile

type Machine {
  Machine(
    complete: Bool,
    verdict: String,
    checks: List(String),
    licences: Option(List(#(String, String))),
    vulnerabilities: Option(
      List(#(String, Option(String), Option(Bool), Option(String))),
    ),
    errors: List(String),
  )
}

fn machine(result: licence_audit.RunResult) -> Machine {
  let decoder = {
    use version <- decode.field("schema_version", decode.int)
    use exit_code <- decode.field("exit_code", decode.int)
    use complete <- decode.field("complete", decode.bool)
    use verdict <- decode.subfield(["summary", "gate_verdict"], decode.string)
    use checks <- decode.subfield(
      ["summary", "checks_run"],
      decode.list(decode.string),
    )
    use licences <- decode.field(
      "licences",
      decode.optional(decode.at(
        ["rows"],
        decode.list({
          use package <- decode.field("package", decode.string)
          use status <- decode.field("status", decode.string)
          decode.success(#(package, status))
        }),
      )),
    )
    use vulnerabilities <- decode.field(
      "vulnerabilities",
      decode.optional(decode.at(
        ["rows"],
        decode.list({
          use id <- decode.field("advisory_id", decode.string)
          use severity <- decode.field(
            "severity",
            decode.optional(decode.string),
          )
          use blocking <- decode.field("blocking", decode.optional(decode.bool))
          use failure <- decode.field(
            "error",
            decode.optional(decode.at(["code"], decode.string)),
          )
          decode.success(#(id, severity, blocking, failure))
        }),
      )),
    )
    use errors <- decode.field(
      "errors",
      decode.list(decode.at(["code"], decode.string)),
    )
    should.equal(version, 1)
    should.equal(exit_code, result.exit_code)
    decode.success(Machine(
      complete:,
      verdict:,
      checks:,
      licences:,
      vulnerabilities:,
      errors:,
    ))
  }
  let assert Ok(value) = json.parse(result.output, decoder)
  value
}

fn project(name: String, names: List(String), policy: String) -> String {
  let root = "build/json-runtime-" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"json_fixture\"\nversion = \"1.0.0\"\n[tools.licence_audit]\n"
        <> policy,
    )
  let packages =
    list.map(names, fn(name) {
      "{name = \""
      <> name
      <> "\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"4C4C81A8F753EE1917FCC9C611745DBB1F8730F2A8B7A1BBDBC9A6B1C69F7A66\"}"
    })
  let assert Ok(_) =
    simplifile.write(
      root <> "/manifest.toml",
      "packages = [" <> string.join(packages, ",") <> "]\n",
    )
  root
}

fn clients() -> licence_audit.Clients {
  let fetch = fn(_) { Ok(hex.licences_only(["MIT"])) }
  licence_audit.Clients(
    ..licence_audit.default_clients(),
    fetcher: fetch,
    notice_clients: source_archive_test.metadata_clients(fetch),
    osv_batch_fetcher: fn(purls) {
      Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, []) }))
    },
    osv_detail_fetcher: fn(_) { Error(osv.NotFound) },
  )
}

fn run(
  root: String,
  args: List(String),
  clients: licence_audit.Clients,
) -> licence_audit.RunResult {
  licence_audit.run_configured(
    list.append(args, ["--manifest=" <> root <> "/manifest.toml"]),
    clients,
    progress.disabled(),
  ).0
}

fn advisory(id: String, severity: osv.Severity) -> osv.Vulnerability {
  osv.Vulnerability(
    id: id,
    aliases: ["CVE-2026-1234"],
    summary: "test advisory",
    severity: severity,
    scores: [],
    affected: [],
  )
}

pub fn text_default_matches_explicit_text_and_bare_report_test() -> Nil {
  let root = project("text", ["example"], "allow = [\"MIT\"]\n")
  let expected = run(root, [], clients())
  should.equal(run(root, ["report"], clients()), expected)
  should.equal(run(root, ["report", "--format=text"], clients()), expected)
  assert !string.starts_with(expected.output, "{")
}

pub fn licence_only_and_combined_complete_results_use_selected_checks_test() -> Nil {
  let root = project("selection", ["example"], "allow = [\"MIT\"]\n")
  use checks <- list.each(["licences", "all"])
  let result =
    run(root, ["check", "--format=json", "--checks=" <> checks], clients())
  should.equal(result.exit_code, 0)
  let document = machine(result)
  should.equal(document.complete, True)
  should.equal(document.verdict, "passed")
  should.equal(document.licences, Some([#("example", "allowed")]))
  case checks {
    "all" -> {
      should.equal(document.checks, ["licences", "vulns"])
      should.equal(document.vulnerabilities, Some([]))
    }
    _ -> {
      should.equal(document.checks, ["licences"])
      should.equal(document.vulnerabilities, None)
    }
  }
}

pub fn vulnerability_only_json_does_not_fetch_or_enforce_licences_test() -> Nil {
  let root = project("vuln-only", ["example"], "")
  let clients =
    licence_audit.Clients(
      ..clients(),
      fetcher: fn(_) { panic as "licence fetch in vulnerability-only check" },
      notice_clients: source_archive_test.metadata_clients(fn(_) {
        panic as "licence archive in vulnerability-only check"
      }),
    )
  let result =
    run(root, ["check", "--checks=vulns", "--format", "json"], clients)
  should.equal(result.exit_code, 0)
  let document = machine(result)
  should.equal(document.licences, None)
  should.equal(document.vulnerabilities, Some([]))
  should.equal(document.checks, ["vulns"])
  should.equal(document.verdict, "passed")
}

pub fn blocking_findings_survive_incomplete_details_and_exit_two_test() -> Nil {
  let root = project("partial-details", ["example"], "allow = [\"MIT\"]\n")
  let clients =
    licence_audit.Clients(
      ..clients(),
      osv_batch_fetcher: fn(purls) {
        Ok(
          list.map(purls, fn(purl) {
            osv.BatchEntry(purl, ["GHSA-high", "GHSA-missing"])
          }),
        )
      },
      osv_detail_fetcher: fn(id) {
        case id {
          "GHSA-high" -> Ok(advisory(id, osv.High))
          _ -> Error(osv.NetworkFailure("detail unavailable"))
        }
      },
    )
  use checks <- list.each(["all", "vulns"])
  let result =
    run(root, ["check", "--checks=" <> checks, "--format=json"], clients)
  should.equal(result.exit_code, 2)
  let document = machine(result)
  should.equal(document.complete, False)
  should.equal(document.verdict, "failed")
  should.equal(
    document.vulnerabilities,
    Some([
      #("GHSA-high", Some("high"), Some(True), None),
      #("GHSA-missing", None, None, Some("osv")),
    ]),
  )
  should.equal(document.errors, ["osv"])
}

pub fn licence_failure_survives_osv_batch_failure_test() -> Nil {
  let root = project("batch-failure", ["example"], "allow = [\"Apache-2.0\"]\n")
  let clients =
    licence_audit.Clients(..clients(), osv_batch_fetcher: fn(_) {
      Error(osv.NetworkFailure("batch unavailable"))
    })
  let result = run(root, ["check", "--checks=all", "--format=json"], clients)
  should.equal(result.exit_code, 2)
  let document = machine(result)
  should.equal(document.licences, Some([#("example", "unallowed")]))
  should.equal(document.verdict, "failed")
  should.equal(document.complete, False)
  should.equal(document.errors, ["osv"])
}

pub fn incomplete_licence_metadata_retains_available_rows_test() -> Nil {
  let root =
    project("metadata", ["healthy", "unavailable"], "allow = [\"MIT\"]\n")
  let clients =
    licence_audit.Clients(
      ..clients(),
      notice_clients: source_archive_test.metadata_clients(fn(name) {
        case name {
          "healthy" -> Ok(hex.licences_only(["MIT"]))
          _ -> Error(hex.NetworkFailure("unavailable"))
        }
      }),
    )
  let result = run(root, ["report", "--format=json"], clients)
  should.equal(result.exit_code, 2)
  let document = machine(result)
  should.equal(document.complete, False)
  should.equal(document.verdict, "not_enforced")
  let assert Some(rows) = document.licences
  assert list.contains(rows, #("healthy", "allowed"))
  assert list.contains(rows, #("unavailable", "failed"))
}

pub fn report_only_incomplete_details_use_null_without_changing_exit_test() -> Nil {
  let root = project("report-details", ["example"], "")
  let clients =
    licence_audit.Clients(..clients(), osv_batch_fetcher: fn(purls) {
      Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, ["GHSA-missing"]) }))
    })
  let result = run(root, ["vulns", "--format=json"], clients)
  should.equal(result.exit_code, 0)
  let document = machine(result)
  should.equal(document.complete, False)
  should.equal(document.verdict, "not_enforced")
  should.equal(document.errors, [])
  should.equal(
    document.vulnerabilities,
    Some([#("GHSA-missing", None, None, Some("osv"))]),
  )
}

pub fn ambiguous_exceptions_retain_fetched_advisory_fields_test() -> Nil {
  let root =
    project(
      "ambiguous-review",
      ["example"],
      "
[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/example@1.0.0\"
finding = \"advisory\"
advisory = \"GHSA-high\"
reason = \"first\"
[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/example@1.0.0\"
finding = \"advisory\"
advisory = \"CVE-2026-1234\"
reason = \"second\"
",
    )
  let clients =
    licence_audit.Clients(
      ..clients(),
      osv_batch_fetcher: fn(purls) {
        Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, ["GHSA-high"]) }))
      },
      osv_detail_fetcher: fn(id) { Ok(advisory(id, osv.High)) },
    )
  use command <- list.each([["vulns"], ["check", "--checks=vulns"]])
  let result = run(root, list.append(command, ["--format=json"]), clients)
  should.equal(result.exit_code, 2)
  let document = machine(result)
  should.equal(document.complete, False)
  should.equal(document.errors, ["config"])
  should.equal(
    document.vulnerabilities,
    Some([#("GHSA-high", Some("high"), None, Some("config"))]),
  )
}

pub fn recognized_json_usage_and_configuration_errors_have_no_clean_results_test() -> Nil {
  let root = project("usage", [], "allow = [\"MIT\"]\n")
  use entry <- list.each([
    #(["check", "--checks=all", "--format=json", "--unknown"], "usage"),
    #(["report", "--format=json", "--quiet", "--verbose"], "usage"),
    #(["check", "--format=json", "--ignore-config"], "missing_policy"),
  ])
  let result = run(root, entry.0, clients())
  should.equal(result.exit_code, 2)
  let document = machine(result)
  should.equal(document.complete, False)
  should.equal(document.licences, None)
  should.equal(document.vulnerabilities, None)
  should.equal(document.errors, [entry.1])
}

pub fn completed_gate_failures_keep_exit_one_and_available_unknown_severity_test() -> Nil {
  let root = project("unknown", ["example"], "")
  let clients =
    licence_audit.Clients(
      ..clients(),
      osv_batch_fetcher: fn(purls) {
        Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, ["GHSA-unknown"]) }))
      },
      osv_detail_fetcher: fn(id) { Ok(advisory(id, osv.UnknownSeverity)) },
    )
  let result =
    run(
      root,
      ["check", "--checks=vulns", "--vuln-block-unknown", "--format=json"],
      clients,
    )
  should.equal(result.exit_code, 1)
  let document = machine(result)
  should.equal(document.complete, True)
  should.equal(document.verdict, "failed")
  should.equal(document.errors, ["audit_failed"])
  should.equal(
    document.vulnerabilities,
    Some([#("GHSA-unknown", Some("unknown"), Some(True), None)]),
  )
}
