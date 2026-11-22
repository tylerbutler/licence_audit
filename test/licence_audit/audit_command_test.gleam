import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/audit_command
import licence_audit/cli
import licence_audit/internal/vendor/glint
import licence_audit/network
import licence_audit/notice
import licence_audit/osv
import licence_audit/policy
import licence_audit/progress
import licence_audit/report
import licence_audit/source_archive
import licence_audit/source_archive_test
import licence_audit/vulnerability_command
import simplifile

fn archives() -> #(BitArray, BitArray) {
  #(
    source_archive_test.metadata_archive(["MIT"]),
    source_archive_test.metadata_archive(["GPL-3.0-only"]),
  )
}

fn options(
  name: String,
  arguments: List(String),
  production: Bool,
  archives: #(BitArray, BitArray),
) -> cli.Options {
  let root = "build/audit-command-test/" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "[tools.licence_audit]\nallow = [\"MIT\"]\ndeny = [\"GPL-3.0-only\"]\n"
        <> case production {
          True -> "[dependencies]\ngood = \"1.0.0\"\nbad = \"1.0.0\"\n"
          False -> "[dev-dependencies]\ngood = \"1.0.0\"\nbad = \"1.0.0\"\n"
        },
    )
  let assert Ok(good_checksum) = source_archive.sha256_hex(archives.0)
  let assert Ok(bad_checksum) = source_archive.sha256_hex(archives.1)
  let assert Ok(_) =
    simplifile.write(
      root <> "/manifest.toml",
      "packages = [
{name = \"good\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> good_checksum <> "\"},
{name = \"bad\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> bad_checksum <> "\"}]
[requirements]
good = \"1.0.0\"
bad = \"1.0.0\"\n",
    )
  let assert Ok(glint.Out(cli.RunAudit(options))) =
    glint.execute(
      cli.app(),
      list.append(["check", "--manifest=" <> root, "--no-cache"], arguments),
    )
  options
}

pub fn empty_production_selection_does_not_fetch_metadata_or_advisories_test() -> Nil {
  let options = options("empty-production", ["--scope=prod"], False, archives())
  let #(result, _) =
    network.with_command(fn() {
      audit_command.run(
        options,
        source_archive_test.metadata_clients(fn(_) {
          panic as "Excluded package metadata must not be fetched"
        }),
        fn(_) { panic as "Vulnerability scan was not selected" },
        fn(_) { panic as "Vulnerability scan was not selected" },
        progress.disabled(),
      )
    })
  let assert Ok(outcome) = result
  should.equal(outcome.licences.rows, [])
  should.equal(outcome.licences.counts.total, 0)
  should.equal(outcome.licences.verdict, audit_command.LicencesPassed)
  should.equal(
    outcome.vulnerabilities.status,
    Ok(vulnerability_command.GateNotEvaluated),
  )
  should.equal(outcome.vulnerabilities.scan_started, False)
}

pub fn failing_tree_selection_does_not_remove_clean_packages_from_domain_counts_test() -> Nil {
  let archives = archives()
  let options = options("full-counts", [], True, archives)
  let #(result, _) =
    network.with_command(fn() {
      audit_command.run(
        options,
        notice.Clients(..notice.default_clients(), fetch_hex_tarball: fn(name, _) {
          case name {
            "good" -> Ok(archives.0)
            "bad" -> Ok(archives.1)
            _ -> panic as "Unexpected package"
          }
        }),
        fn(_) { panic as "Vulnerability scan was not selected" },
        fn(_) { panic as "Vulnerability scan was not selected" },
        progress.disabled(),
      )
    })
  let assert Ok(outcome) = result
  should.equal(list.length(outcome.licences.rows), 2)
  should.equal(outcome.licences.counts.total, 2)
  should.equal(outcome.licences.counts.allowed, 1)
  should.equal(outcome.licences.counts.denied, 1)
  should.equal(outcome.licences.verdict, audit_command.LicencesBlocked)
  should.equal(outcome.licences.completeness, vulnerability_command.CheckComplete)
  let assert Ok(denied) = list.find(outcome.licences.rows, fn(row) { row.package == "bad" })
  should.equal(denied.status, report.Checked(policy.DeniedLicence("GPL-3.0-only")))
}

pub fn incomplete_combined_scan_retains_enforced_findings_and_typed_detail_failures_test() -> Nil {
  let archives = archives()
  let options = options("partial", ["--checks=all"], True, archives)
  let #(result, _) =
    network.with_command(fn() {
      audit_command.run(
        options,
        notice.Clients(..notice.default_clients(), fetch_hex_tarball: fn(name, _) {
          case name {
            "bad" -> Ok(archives.1)
            "good" -> Error(notice.FetchNetworkFailure)
            _ -> panic as "Unexpected package"
          }
        }),
        fn(purls) {
          Ok(list.map(purls, fn(purl) {
            osv.BatchEntry(purl, ["GHSA-high", "GHSA-missing"])
          }))
        },
        fn(id) {
          case id {
            "GHSA-high" ->
              Ok(osv.Vulnerability(
                id: id,
                aliases: [],
                summary: "Blocking advisory",
                severity: osv.High,
                scores: [],
                affected: [],
              ))
            "GHSA-missing" -> Error(osv.NotFound)
            _ -> panic as "Unexpected advisory"
          }
        },
        progress.capturing(progress.Normal, "check"),
      )
    })
  let assert Ok(outcome) = result
  should.equal(outcome.review_failure, None)
  should.equal(outcome.licences.verdict, audit_command.LicencesBlocked)
  should.equal(outcome.licences.completeness, vulnerability_command.CheckIncomplete)
  should.equal(outcome.licences.counts.total, 2)
  should.equal(outcome.licences.counts.denied, 1)
  should.equal(outcome.licences.counts.unknown, 1)
  let assert Ok(denied) = list.find(outcome.licences.rows, fn(row) { row.package == "bad" })
  should.equal(denied.status, report.Checked(policy.DeniedLicence("GPL-3.0-only")))
  let gate = outcome.vulnerabilities
  should.equal(
    gate.status,
    Ok(vulnerability_command.GateEvaluated(
      vulnerability_command.BlockingKnownSeverity,
      vulnerability_command.CheckIncomplete,
    )),
  )
  should.equal(gate.scan_started, True)
  should.equal(list.length(gate.occurrences), 2)
  assert list.all(gate.occurrences, fn(occurrence) {
    occurrence.blocking == Some(True)
  })
  let assert [failure] = gate.detail_failures
  should.equal(failure.id, "GHSA-missing")
  should.equal(failure.runtime_failed, False)
  assert string.contains(failure.reason, "OSV resource not found")
}
