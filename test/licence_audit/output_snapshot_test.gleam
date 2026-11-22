import birdie
import gleam/list
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/hex
import licence_audit/manifest
import licence_audit/notice
import licence_audit/osv
import licence_audit/progress
import licence_audit/source_archive_test
import simplifile

const policy =
  "[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\", \"GPL-3.0\"]\n"

const denied_policy =
  "[tools.licence_audit]\nallow = [\"MIT\", \"Apache-2.0\"]\ndeny = [\"GPL-3.0\"]\n"

const licence_exception =
  "\n[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/lib_c@3.0.0\"
finding = \"denied-licence\"
licence = \"GPL-3.0\"
reason = \"Reviewed use\"
"

fn project(
  name: String,
  manifest_fixture: String,
  configuration: String,
) -> String {
  let root = "build/tmp/output_snapshots/" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(contents) = simplifile.read(manifest_fixture)
  let assert Ok(_) = simplifile.write(root <> "/manifest.toml", contents)
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"snapshot_fixture\"\nversion = \"1.0.0\"\n"
        <> "[dependencies]\napp_a = \"1.0.0\"\ngleam_stdlib = \"1.0.0\"\n"
        <> "[dev-dependencies]\nargv = \"1.1.0\"\n"
        <> configuration,
    )
  root
}

fn metadata(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "app_a" | "lib_b" | "gleam_stdlib" -> Ok(hex.licences_only(["MIT"]))
    "lib_c" -> Ok(hex.licences_only(["GPL-3.0"]))
    "argv" -> Ok(hex.licences_only(["Apache-2.0"]))
    _ -> panic as "unexpected snapshot package"
  }
}

fn clients() -> licence_audit.Clients {
  licence_audit.Clients(
    fetcher: fn(_) { panic as "reports must read locked source metadata" },
    publication_fetcher: fn(_, _) {
      panic as "snapshots must not verify publications"
    },
    notice_clients: source_archive_test.metadata_clients(metadata),
    osv_batch_fetcher: fn(_) {
      panic as "licence-only snapshots must not query OSV"
    },
    osv_detail_fetcher: fn(_) {
      panic as "licence-only snapshots must not fetch advisories"
    },
  )
}

fn run(
  root: String,
  command: List(String),
  clients: licence_audit.Clients,
) -> licence_audit.RunResult {
  let #(result, events) =
    licence_audit.run_configured(
      list.append(command, [
        "--manifest=" <> root <> "/manifest.toml",
        "--config=" <> root <> "/gleam.toml",
        "--color=never",
        "--quiet",
      ]),
      clients,
      progress.disabled(),
    )
  should.equal(events, [])
  assert !string.contains(result.output, "\u{001b}[")
  result
}

fn licence_output(
  name: String,
  configuration: String,
  command: List(String),
  expected_exit: Int,
) -> String {
  let fixture = case name {
    "skipped sources" -> "test/fixtures/manifest.toml"
    _ -> "test/fixtures/transitive_manifest.toml"
  }
  let root = project(name, fixture, configuration)
  let root_report = run(root, [], clients())
  should.equal(root_report.exit_code, 0)
  should.equal(run(root, ["report"], clients()), root_report)
  let result = run(root, command, clients())
  should.equal(result.exit_code, expected_exit)
  result.output
}

pub fn root_report_pass_test() -> Nil {
  licence_output("pass", policy, [], 0)
  |> birdie.snap("root report pass")
}

pub fn root_report_fail_test() -> Nil {
  licence_output("fail", denied_policy, [], 0)
  |> birdie.snap("root report fail")
}

pub fn root_report_exception_test() -> Nil {
  licence_output("exception", denied_policy <> licence_exception, [], 0)
  |> birdie.snap("root report exception")
}

pub fn root_report_skipped_sources_test() -> Nil {
  licence_output("skipped sources", policy, [], 0)
  |> birdie.snap("root report skipped sources")
}

pub fn check_licences_pass_test() -> Nil {
  licence_output("pass", policy, ["check"], 0)
  |> birdie.snap("check licences pass")
}

pub fn check_licences_fail_test() -> Nil {
  licence_output("fail", denied_policy, ["check"], 1)
  |> birdie.snap("check licences fail")
}

pub fn check_licences_exception_test() -> Nil {
  licence_output("exception", denied_policy <> licence_exception, ["check"], 0)
  |> birdie.snap("check licences exception")
}

pub fn check_licences_skipped_sources_test() -> Nil {
  licence_output("skipped sources", policy, ["check"], 0)
  |> birdie.snap("check licences skipped sources")
}

fn vulnerable_batch(
  purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  should.equal(list.sort(purls, string.compare), [
    "pkg:hex/argv@1.1.0",
    "pkg:hex/gleam_stdlib@1.0.0",
  ])
  Ok(
    list.map(purls, fn(purl) {
      osv.BatchEntry(purl:, vuln_ids: case purl {
        "pkg:hex/gleam_stdlib@1.0.0" -> ["GHSA-snapshot"]
        _ -> []
      })
    }),
  )
}

fn advisory(id: String) -> Result(osv.Vulnerability, osv.Error) {
  should.equal(id, "GHSA-snapshot")
  Ok(
    osv.Vulnerability(
      id:,
      aliases: ["CVE-2026-12345"],
      summary: "Malformed input can interrupt request handling.",
      severity: osv.High,
      affected: [],
      scores: [
        osv.Score(
          kind: "CVSS_V3",
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
      ],
    ),
  )
}

fn vulnerability_clients() -> licence_audit.Clients {
  licence_audit.Clients(
    ..clients(),
    osv_batch_fetcher: vulnerable_batch,
    osv_detail_fetcher: advisory,
  )
}

pub fn vulns_descriptive_report_test() -> Nil {
  let root = project("vulnerabilities", "test/fixtures/manifest.toml", policy)
  let report = run(root, ["vulns"], vulnerability_clients())
  should.equal(report.exit_code, 0)
  birdie.snap(report.output, "vulns descriptive report")
}

pub fn check_vulns_gate_test() -> Nil {
  let root = project("vulnerabilities", "test/fixtures/manifest.toml", policy)
  let only_vulnerabilities =
    run(
      root,
      ["check", "--checks=vulns"],
      licence_audit.Clients(
        ..vulnerability_clients(),
        notice_clients: source_archive_test.metadata_clients(fn(_) {
          panic as "vulnerability-only checks must not fetch licences"
        }),
      ),
    )
  should.equal(only_vulnerabilities.exit_code, 1)
  birdie.snap(only_vulnerabilities.output, "check vulns gate")
}

pub fn check_all_gates_test() -> Nil {
  let root = project("vulnerabilities", "test/fixtures/manifest.toml", policy)
  let all = run(root, ["check", "--checks=all"], vulnerability_clients())
  should.equal(all.exit_code, 1)
  birdie.snap(all.output, "check all gates")
}

pub fn small_notices_document_test() -> Nil {
  let entries =
    list.map(["beta", "alpha"], fn(name) {
      notice.NoticeEntry(
        package: notice.NoticePackage(
          name:,
          version: "1.0.0",
          declared_licences: ["MIT"],
          repo_links: [],
          source: notice.HexPackage(outer_checksum: "AAAA"),
          scope: manifest.Prod,
        ),
        files: [
          notice.NoticeFile("LICENSE", "Shared fixture licence text.\n"),
          ..case name {
            "beta" -> [notice.NoticeFile("NOTICE", "Beta attribution.\n")]
            _ -> []
          }
        ],
      )
    })
  let document = notice.render(entries, manifest_path: "manifest.toml")
  should.equal(
    notice.render(list.reverse(entries), manifest_path: "manifest.toml"),
    document,
  )
  birdie.snap(document, "small notices document")
}

fn help_output(command: List(String)) -> String {
  let #(result, events) =
    licence_audit.run_configured(
      list.append(command, ["--help"]),
      licence_audit.Clients(
        ..clients(),
        notice_clients: source_archive_test.metadata_clients(fn(_) {
          panic as "help must not fetch locked source metadata"
        }),
      ),
      progress.disabled(),
    )
  should.equal(result.exit_code, 0)
  should.equal(events, [])
  assert !string.contains(result.output, "\u{001b}[")
  result.output
}

pub fn root_help_test() -> Nil {
  help_output([])
  |> birdie.snap("root help")
}

pub fn report_help_test() -> Nil {
  help_output(["report"])
  |> birdie.snap("report help")
}

pub fn check_help_test() -> Nil {
  help_output(["check"])
  |> birdie.snap("check help")
}

pub fn update_help_test() -> Nil {
  help_output(["update"])
  |> birdie.snap("update help")
}

pub fn sbom_help_test() -> Nil {
  help_output(["sbom"])
  |> birdie.snap("sbom help")
}

pub fn vulns_help_test() -> Nil {
  help_output(["vulns"])
  |> birdie.snap("vulns help")
}

pub fn notices_help_test() -> Nil {
  help_output(["notices"])
  |> birdie.snap("notices help")
}
