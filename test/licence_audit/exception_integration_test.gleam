import gleam/int
import gleam/list
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/hex
import licence_audit/osv
import simplifile

const manifest = "packages = [
{ name = \"first\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"AAAA\", requirements = [] },
{ name = \"second\", version = \"2.0.0\", source = \"hex\", outer_checksum = \"BBBB\", requirements = [] },
{ name = \"git_dep\", version = \"0.1.0\", source = \"git\", repo = \"https://github.com/owner/repo\", commit = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", requirements = [] },
{ name = \"local_dep\", version = \"0.1.0\", source = \"path\", path = \"local\", requirements = [] }
]
[requirements]
first = { version = \"1.0.0\" }
second = { version = \"2.0.0\" }
git_dep = { git = \"https://github.com/owner/repo\", ref = \"main\" }
"

const licence_rules = "[tools.licence_audit]\nallow = [\"MIT\"]\ndeny = [\"GPL-3.0-only\"]\n"

fn waiver(purl: String, selector: String, extra: String) -> String {
  "\n[[tools.licence_audit.exceptions]]\npurl = \""
  <> purl
  <> "\"\nfinding = \""
  <> selector
  <> "\"\nreason = \"Reviewed scope\"\n"
  <> extra
  <> "\n"
}

fn licence_waiver(extra: String) -> String {
  waiver(
    "pkg:hex/first@1.0.0",
    "denied-licence",
    "licence = \"GPL-3.0-only\"\n" <> extra,
  )
}

fn advisory_waiver(purl: String, id: String, extra: String) -> String {
  waiver(purl, "advisory", "advisory = \"" <> id <> "\"\n" <> extra)
}

fn project(name: String, policy: String) -> String {
  let root = "build/tmp/exception_tests/" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(contents: manifest, to: root <> "/manifest.toml")
  let assert Ok(_) =
    simplifile.write(
      contents: "name = \"fixture\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]\n"
        <> "[dependencies]\nfirst = \"1.0.0\"\n"
        <> "[dev-dependencies]\nsecond = \"2.0.0\"\n"
        <> policy,
      to: root <> "/gleam.toml",
    )
  root
}

fn licences(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  Ok(
    hex.licences_only(case name {
      "first" -> ["GPL-3.0-only"]
      _ -> ["MIT"]
    }),
  )
}

fn clean_licences(_name: String) -> Result(hex.PackageMetadata, hex.Error) {
  Ok(hex.licences_only(["MIT"]))
}

fn batch(purls: List(String)) -> Result(List(osv.BatchEntry), osv.Error) {
  Ok(
    list.map(purls, fn(purl) { osv.BatchEntry(purl:, vuln_ids: ["OSV-lookup"]) }),
  )
}

fn first_batch(purls: List(String)) -> Result(List(osv.BatchEntry), osv.Error) {
  Ok(
    list.map(purls, fn(purl) {
      osv.BatchEntry(purl:, vuln_ids: case purl == "pkg:hex/first@1.0.0" {
        True -> ["OSV-lookup"]
        False -> []
      })
    }),
  )
}

fn detail(_id: String) -> Result(osv.Vulnerability, osv.Error) {
  Ok(
    osv.Vulnerability(
      id: "GHSA-canonical",
      aliases: ["CVE-2026-12345"],
      summary: "Affected feature",
      severity: osv.High,
      scores: [],
    ),
  )
}

fn run(
  root: String,
  args: List(String),
  fetch: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  query: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  details: fn(String) -> Result(osv.Vulnerability, osv.Error),
) -> licence_audit.RunResult {
  licence_audit.run_with_clients(
    list.append(args, [
      "--manifest=" <> root <> "/manifest.toml",
      "--color=never",
      "--quiet",
    ]),
    fetch,
    query,
    details,
  )
}

pub fn matching_licence_exception_overrides_deny_without_changing_evidence_test() {
  let root = project("licence_match", licence_rules <> licence_waiver(""))
  let result = run(root, ["check"], licences, batch, detail)
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "denied: GPL-3.0-only [excepted #1")
  assert string.contains(result.output, "Reviewed scope (no expiry)")
  assert string.contains(result.output, "Policy exceptions:")
  assert string.contains(result.output, "local_dep")
  let preview = run(root, [], licences, batch, detail)
  should.equal(preview.exit_code, 0)
  assert string.contains(preview.output, "excepted #1")
  let ignored =
    run(
      root,
      ["check", "--ignore-config", "--allow=MIT", "--deny=GPL-3.0-only"],
      licences,
      batch,
      detail,
    )
  should.equal(ignored.exit_code, 1)
  assert !string.contains(ignored.output, "Policy exceptions:")
}

pub fn accepted_licence_cannot_hide_a_second_finding_or_tree_test() {
  let root = project("multiple_findings", licence_rules <> licence_waiver(""))
  let fetch = fn(_name) {
    Ok(hex.licences_only(["GPL-3.0-only", "Apache-2.0"]))
  }
  let result = run(root, ["check"], fetch, batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "denied: GPL-3.0-only [excepted #1")
  assert string.contains(result.output, "unknown: Apache-2.0")
  assert string.contains(result.output, "second")
  let fetch = fn(name) {
    Ok(
      hex.licences_only(case name {
        "first" -> ["GPL-3.0-only"]
        _ -> ["Apache-2.0"]
      }),
    )
  }
  let result = run(root, ["check"], fetch, batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "first")
  assert string.contains(result.output, "excepted #1")
}

pub fn expired_and_updated_scope_do_not_accept_findings_test() {
  let root =
    project(
      "expired",
      licence_rules <> licence_waiver("expires = \"2000-01-01\""),
    )
  let result = run(root, ["check"], licences, batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "expired; matched")
  let root =
    project(
      "updated",
      licence_rules
        <> string.replace(licence_waiver(""), "first@1.0.0", "first@0.9.0"),
    )
  let result = run(root, ["check"], licences, batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "unused #1")
  let result = run(root, ["check"], clean_licences, batch, detail)
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "unused #1")
}

pub fn missing_metadata_exception_never_accepts_fetch_errors_test() {
  let root =
    project(
      "missing_metadata",
      licence_rules <> waiver("pkg:hex/first@1.0.0", "no-licences-declared", ""),
    )
  let result =
    run(
      root,
      ["check"],
      fn(name) {
        case name {
          "first" -> Ok(hex.licences_only([]))
          _ -> clean_licences(name)
        }
      },
      batch,
      detail,
    )
  should.equal(result.exit_code, 0)
  let result =
    run(
      root,
      ["check"],
      fn(name) {
        case name {
          "first" -> Error(hex.InvalidMetadata("invalid licence data"))
          _ -> clean_licences(name)
        }
      },
      batch,
      detail,
    )
  should.equal(result.exit_code, 2)
  assert string.contains(
    result.output,
    "not evaluated: licence metadata unavailable",
  )
  assert !string.contains(result.output, "excepted #1")
}

pub fn advisory_alias_accepts_only_one_package_occurrence_test() {
  let root =
    project(
      "one_advisory",
      licence_rules
        <> advisory_waiver("pkg:hex/first@1.0.0", "CVE-2026-12345", ""),
    )
  let result =
    run(root, ["check", "--vulns"], clean_licences, first_batch, detail)
  should.equal(result.exit_code, 0)
  assert string.contains(
    result.output,
    "GHSA-canonical  first@1.0.0 [excepted #1",
  )
  let result = run(root, ["check", "--vulns"], clean_licences, batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "1 blocking advisory/advisories")
  assert string.contains(result.output, "second@2.0.0")
  assert string.contains(
    result.output,
    "Skipped 1 unsupported source(s): local_dep",
  )
}

pub fn expired_and_unrelated_advisories_follow_normal_gate_test() {
  let root =
    project(
      "expired_advisory",
      licence_rules
        <> advisory_waiver(
        "pkg:hex/first@1.0.0",
        "CVE-2026-12345",
        "expires = \"2000-01-01\"",
      ),
    )
  let result =
    run(root, ["check", "--vulns"], clean_licences, first_batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "expired; matched")
  let result =
    run(
      root,
      ["check", "--vulns", "--vuln-severity=critical"],
      clean_licences,
      first_batch,
      detail,
    )
  should.equal(result.exit_code, 0)
  let root =
    project(
      "unrelated_advisory",
      licence_rules
        <> advisory_waiver("pkg:hex/first@1.0.0", "CVE-2026-99999", ""),
    )
  let result =
    run(root, ["check", "--vulns"], clean_licences, first_batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "unused #1")
}

pub fn all_scoped_advisories_can_be_accepted_including_github_test() {
  let root =
    project(
      "all_advisories",
      licence_rules
        <> advisory_waiver("pkg:hex/first@1.0.0", "GHSA-canonical", "")
        <> advisory_waiver("pkg:hex/second@2.0.0", "CVE-2026-12345", "")
        <> advisory_waiver(
        "pkg:github/owner/repo@" <> string.repeat("a", 40),
        "GHSA-canonical",
        "",
      ),
    )
  let result = run(root, ["check", "--vulns"], clean_licences, batch, detail)
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "3 excepted finding(s)")
  let assert Ok(contents) = simplifile.read(root <> "/manifest.toml")
  let assert Ok(_) =
    simplifile.write(
      contents: string.replace(
        contents,
        string.repeat("a", 40),
        string.repeat("b", 40),
      ),
      to: root <> "/manifest.toml",
    )
  let result = run(root, ["check", "--vulns"], clean_licences, batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "unused #3")
}

pub fn advisory_overlap_is_a_config_error_in_both_commands_test() {
  let root =
    project(
      "overlap",
      licence_rules
        <> advisory_waiver("pkg:hex/first@1.0.0", "GHSA-canonical", "")
        <> advisory_waiver("pkg:hex/first@1.0.0", "CVE-2026-12345", ""),
    )
  [["check", "--vulns"], ["vulns"]]
  |> list.each(fn(args) {
    let result = run(root, args, clean_licences, first_batch, detail)
    should.equal(result.exit_code, 2)
    assert string.contains(result.output, "exceptions[1] and exceptions[2]")
  })
}

pub fn ambiguous_locked_identity_is_rejected_before_osv_query_test() {
  let root =
    project(
      "ambiguous_identity",
      licence_rules
        <> advisory_waiver(
        "pkg:github/owner/repo@" <> string.repeat("a", 40),
        "CVE-2026-12345",
        "",
      ),
    )
  let duplicate =
    "{ name = \"another_git\", version = \"0.1.0\", source = \"git\", repo = \"https://github.com/owner/repo\", commit = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", requirements = [] },"
  let assert Ok(_) =
    simplifile.write(
      to: root <> "/manifest.toml",
      contents: string.replace(
        manifest,
        "packages = [",
        "packages = [\n" <> duplicate,
      ),
    )
  [["check", "--vulns"], ["vulns"]]
  |> list.each(fn(args) {
    let result =
      run(
        root,
        args,
        clean_licences,
        fn(_) { panic as "must not query ambiguous identity" },
        detail,
      )
    should.equal(result.exit_code, 2)
    assert string.contains(
      result.output,
      "purl matches multiple locked packages",
    )
  })
}

pub fn accepted_advisory_cannot_hide_another_advisory_or_licence_test() {
  let root =
    project(
      "isolated_advisory",
      licence_rules
        <> advisory_waiver("pkg:hex/first@1.0.0", "CVE-2026-12345", ""),
    )
  let result = run(root, ["check", "--vulns"], licences, first_batch, detail)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "denied: GPL-3.0-only")
  let query = fn(purls) {
    Ok(
      list.map(purls, fn(purl) {
        osv.BatchEntry(purl:, vuln_ids: ["OSV-lookup", "OSV-other"])
      }),
    )
  }
  let details = fn(id) {
    case id {
      "OSV-other" ->
        Ok(
          osv.Vulnerability(
            id:,
            aliases: [],
            summary: "",
            severity: osv.Critical,
            scores: [],
          ),
        )
      _ -> detail(id)
    }
  }
  let result = run(root, ["check", "--vulns"], clean_licences, query, details)
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "OSV-other")
}

pub fn failed_osv_evidence_is_never_excepted_test() {
  let root =
    project(
      "osv_failure",
      licence_rules <> advisory_waiver("pkg:hex/first@1.0.0", "OSV-lookup", ""),
    )
  let result =
    run(
      root,
      ["check", "--vulns"],
      clean_licences,
      fn(_) { Error(osv.NetworkFailure) },
      detail,
    )
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "not evaluated: OSV request failed")
  let failed = fn(_) { Error(osv.InvalidJson("Invalid response")) }
  let result =
    run(root, ["check", "--vulns"], clean_licences, first_batch, failed)
  should.equal(result.exit_code, 2)
  assert string.contains(
    result.output,
    "not evaluated: OSV advisory details unavailable",
  )
  let result = run(root, ["vulns"], clean_licences, first_batch, failed)
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "(details unavailable)")
  assert !string.contains(result.output, "excepted #1")
}

pub fn standalone_vulns_loads_config_and_reports_without_enforcement_test() {
  let root =
    project(
      "standalone",
      licence_rules
        <> advisory_waiver("pkg:hex/first@1.0.0", "CVE-2026-12345", "")
        <> licence_waiver(""),
    )
  let result = run(root, ["vulns"], clean_licences, batch, detail)
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "3 with vulnerabilities, 0 clean")
  assert string.contains(result.output, "1 excepted finding(s)")
  assert string.contains(result.output, "not evaluated: licence scan disabled")
  let ignored =
    run(root, ["vulns", "--ignore-config"], clean_licences, batch, detail)
  should.equal(ignored.exit_code, 0)
  assert !string.contains(ignored.output, "Policy exceptions:")
  let alternate = root <> "/other.toml"
  let assert Ok(_) =
    simplifile.write(
      contents: licence_rules
        <> advisory_waiver(
        "pkg:hex/first@1.0.0",
        "CVE-2026-12345",
        "expires = \"2000-01-01\"",
      ),
      to: alternate,
    )
  let result =
    run(
      root,
      ["vulns", "--config=" <> alternate],
      clean_licences,
      first_batch,
      detail,
    )
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "expired; matched")
}

pub fn disabled_and_production_filtered_scans_are_not_unused_test() {
  let root =
    project(
      "filtered",
      licence_rules
        <> advisory_waiver("pkg:hex/second@2.0.0", "CVE-2026-12345", "")
        <> string.replace(licence_waiver(""), "first@1.0.0", "second@2.0.0"),
    )
  let result = run(root, ["check"], clean_licences, batch, detail)
  assert string.contains(
    result.output,
    "not evaluated: vulnerability scan disabled",
  )
  let result =
    run(
      root,
      ["check", "--vulns", "--prod-only"],
      clean_licences,
      first_batch,
      detail,
    )
  should.equal(result.exit_code, 1)
  assert string.contains(
    result.output,
    "not evaluated: excluded by --prod-only #1",
  )
  assert string.contains(
    result.output,
    "not evaluated: excluded by --prod-only #2",
  )
}

pub fn unknown_severity_obeys_exception_and_existing_threshold_rules_test() {
  let root =
    project(
      "unknown",
      licence_rules
        <> advisory_waiver("pkg:hex/first@1.0.0", "CVE-2026-12345", ""),
    )
  let details = fn(id) {
    let assert Ok(vuln) = detail(id)
    Ok(osv.Vulnerability(..vuln, severity: osv.UnknownSeverity))
  }
  let result =
    run(
      root,
      ["check", "--vulns", "--vuln-block-unknown"],
      clean_licences,
      first_batch,
      details,
    )
  should.equal(result.exit_code, 0)
  let result =
    run(
      root,
      ["check", "--vulns", "--vuln-block-unknown"],
      clean_licences,
      batch,
      details,
    )
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "unknown-severity blocking rule")
}

pub fn malformed_exceptions_fail_before_fetching_test() {
  let root = project("invalid", licence_rules <> licence_waiver("typo = true"))
  [["check"], ["vulns"]]
  |> list.each(fn(args) {
    let result =
      run(
        root,
        args,
        fn(_) { panic as "must not fetch" },
        fn(_) { panic as "must not query" },
        detail,
      )
    should.equal(result.exit_code, 2)
    assert string.contains(result.output, "exceptions[1]")
  })
}

pub fn no_exception_output_is_unchanged_test() {
  let root = project("empty", licence_rules)
  let first =
    run(root, ["check", "--vulns"], clean_licences, first_batch, detail)
  let assert Ok(contents) = simplifile.read(root <> "/gleam.toml")
  let assert Ok(_) =
    simplifile.write(
      contents: contents <> "\nexceptions = []\n",
      to: root <> "/gleam.toml",
    )
  let second =
    run(root, ["check", "--vulns"], clean_licences, first_batch, detail)
  should.equal(second, first)
}

pub fn unused_expired_entries_do_not_fail_on_their_own_test() {
  [0, 1]
  |> list.each(fn(index) {
    let root =
      project(
        "unused_expired_" <> int.to_string(index),
        licence_rules
          <> advisory_waiver(
          "pkg:hex/absent@1.0.0",
          "CVE-2026-12345",
          "expires = \"2000-01-01\"",
        ),
      )
    let query = fn(purls) {
      Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl:, vuln_ids: []) }))
    }
    let result =
      run(
        root,
        case index {
          0 -> ["check", "--vulns"]
          _ -> ["vulns"]
        },
        clean_licences,
        query,
        detail,
      )
    should.equal(result.exit_code, 0)
    assert string.contains(result.output, "expired; unused")
  })
}
