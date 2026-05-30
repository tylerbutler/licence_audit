import gleam/list
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/hex
import licence_audit/osv
import licence_audit/progress
import simplifile

fn fake_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "gleam_stdlib" -> Ok(hex.PackageMetadata(licences: ["MIT"]))
    "argv" -> Ok(hex.PackageMetadata(licences: ["Apache-2.0"]))
    _ -> Error(hex.NotFound)
  }
}

fn failing_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "argv" -> Error(hex.NotFound)
    _ -> fake_fetcher(name)
  }
}

fn manifest_args(extra: List(String)) -> List(String) {
  list.append(
    ["--manifest=test/fixtures/manifest.toml", "--ignore-config"],
    extra,
  )
}

pub fn default_report_succeeds_without_policy_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(manifest_args([]), fake_fetcher)

  should.equal(exit_code, 0)
  assert string.contains(output, "Package")
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "MIT")
  assert string.contains(output, "argv")
  assert string.contains(output, "Apache-2.0")
  assert !string.contains(output, "Status")
}

pub fn normal_progress_reports_audit_phases_without_package_details_test() {
  let #(licence_audit.RunResult(exit_code, _), events) =
    licence_audit.run_with_progress(
      manifest_args([]),
      fake_fetcher,
      progress.Normal,
    )

  should.equal(exit_code, 0)
  should.equal(events, [
    progress.Event(progress.Phase, "Starting licence audit"),
    progress.Event(progress.PackageCount, "Checking Hex package metadata"),
    progress.Event(progress.Success, "Licence audit completed"),
  ])
}

pub fn quiet_progress_reports_no_events_test() {
  let #(licence_audit.RunResult(exit_code, output), events) =
    licence_audit.run_with_progress(
      manifest_args(["--quiet"]),
      fake_fetcher,
      progress.Quiet,
    )

  should.equal(exit_code, 0)
  assert string.contains(output, "Package")
  should.equal(events, [])
}

pub fn verbose_progress_includes_package_details_test() {
  let #(licence_audit.RunResult(exit_code, output), events) =
    licence_audit.run_with_progress(
      manifest_args(["--verbose"]),
      fake_fetcher,
      progress.Verbose,
    )

  should.equal(exit_code, 0)
  assert string.contains(output, "Package")
  assert list.contains(
    events,
    progress.Event(progress.Detail, "Fetched package metadata for gleam_stdlib"),
  )
  assert !string.contains(output, "Fetched package metadata for gleam_stdlib")
  assert !string.contains(output, "Licence audit completed")
}

pub fn all_allowed_dependencies_pass_in_check_mode_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(
      manifest_args(["check", "--allow=MIT,Apache-2.0"]),
      fake_fetcher,
    )

  should.equal(exit_code, 0)
  assert string.contains(output, "Status")
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "allowed")
  assert !string.contains(output, "Dependency licence audit failed")
}

pub fn missing_policy_in_check_mode_exits_two_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(manifest_args(["check"]), fake_fetcher)

  should.equal(exit_code, 2)
  assert string.contains(
    output,
    "No licence policy supplied for the `check` subcommand",
  )
}

pub fn denied_dependency_fails_in_check_mode_with_report_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(
      manifest_args([
        "check",
        "--allow=MIT,Apache-2.0",
        "--deny=MIT",
      ]),
      fake_fetcher,
    )

  should.equal(exit_code, 1)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "denied: MIT")
  assert string.contains(output, "Dependency licence audit failed")
}

pub fn policy_failure_emits_error_progress_event_test() {
  let #(licence_audit.RunResult(exit_code, _), events) =
    licence_audit.run_with_progress(
      manifest_args(["check", "--allow=MIT,Apache-2.0", "--deny=MIT"]),
      fake_fetcher,
      progress.Normal,
    )

  should.equal(exit_code, 1)
  assert list.contains(
    events,
    progress.Event(
      progress.Error,
      "Licence audit failed: policy violations detected",
    ),
  )
}

pub fn fetch_failure_in_check_mode_emits_error_progress_event_test() {
  let #(licence_audit.RunResult(exit_code, _), events) =
    licence_audit.run_with_progress(
      manifest_args(["check", "--allow=MIT,Apache-2.0"]),
      failing_fetcher,
      progress.Normal,
    )

  should.equal(exit_code, 2)
  assert list.contains(
    events,
    progress.Event(
      progress.Error,
      "Licence audit failed: package metadata could not be fetched",
    ),
  )
}

pub fn path_and_git_packages_are_skipped_and_counted_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(manifest_args([]), fake_fetcher)

  should.equal(exit_code, 0)
  // Non-Hex packages now appear in the tree (so their place in the dependency
  // graph is visible) but are still tallied in the skipped summary.
  assert string.contains(output, "local_dep")
  assert string.contains(output, "git_dep")
  assert string.contains(output, "non-hex (path)")
  assert string.contains(output, "non-hex (git)")
  assert string.contains(output, "Skipped non-Hex packages: 2")
}

pub fn hex_fetch_failure_in_report_mode_exits_zero_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(manifest_args([]), failing_fetcher)

  should.equal(exit_code, 0)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "argv")
  assert string.contains(output, "Hex package not found")
}

pub fn hex_fetch_failure_in_check_mode_exits_two_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(
      manifest_args(["check", "--allow=MIT,Apache-2.0"]),
      failing_fetcher,
    )

  should.equal(exit_code, 2)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "argv")
  assert string.contains(output, "Hex package not found")
}

fn transitive_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "app_a" -> Ok(hex.PackageMetadata(licences: ["MIT"]))
    "lib_b" -> Ok(hex.PackageMetadata(licences: ["MIT"]))
    "lib_c" -> Ok(hex.PackageMetadata(licences: ["GPL-3.0"]))
    _ -> Error(hex.NotFound)
  }
}

fn transitive_manifest_args(extra: List(String)) -> List(String) {
  list.append(
    [
      "--manifest=test/fixtures/transitive_manifest.toml",
      "--ignore-config",
    ],
    extra,
  )
}

pub fn report_tags_direct_and_transitive_kinds_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(transitive_manifest_args([]), transitive_fetcher)

  should.equal(exit_code, 0)
  assert !string.contains(output, "Kind")
  // app_a is the direct dep, lib_b and lib_c are transitive.
  assert string.contains(output, "app_a")
  assert string.contains(output, "lib_b")
  assert string.contains(output, "lib_c")
}

pub fn denied_transitive_fails_check_and_prints_via_chain_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(
      transitive_manifest_args([
        "check",
        "--allow=MIT",
        "--deny=GPL-3.0",
      ]),
      transitive_fetcher,
    )

  should.equal(exit_code, 1)
  assert string.contains(output, "lib_c")
  assert string.contains(output, "denied: GPL-3.0")
  // The tree layout indents transitive deps under the dep that brought them
  // in: app_a → lib_b → lib_c.
  assert string.contains(output, "└─ ✓ lib_b")
  assert string.contains(output, "   └─ ✗ lib_c")
  assert string.contains(output, "Dependency licence audit failed")
}

pub fn direct_dep_denial_does_not_emit_via_line_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(
      transitive_manifest_args([
        "check",
        "--allow=GPL-3.0",
        "--deny=MIT",
      ]),
      transitive_fetcher,
    )

  should.equal(exit_code, 1)
  assert string.contains(output, "app_a")
  assert string.contains(output, "denied: MIT")
  // A direct dep alone never produces a `via:` chain — the only via line in
  // this output, if any, belongs to the transitive lib_b → app_a chain.
  assert !string.contains(output, "via: app_a\n")
}

pub fn check_failure_only_reports_failing_trees_test() {
  // gleam_stdlib (MIT) is denied; argv (Apache-2.0) is allowed and lives in
  // its own root-level tree. On policy failure the report should omit the
  // passing tree and only show the offending one.
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with(
      manifest_args([
        "check",
        "--allow=MIT,Apache-2.0",
        "--deny=MIT",
      ]),
      fake_fetcher,
    )

  should.equal(exit_code, 1)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "denied: MIT")
  assert !string.contains(output, "argv")
}

fn failing_osv_batch(
  _purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  Error(osv.NetworkFailure)
}

fn unused_vuln_detail(_id: String) -> Result(osv.Vulnerability, osv.Error) {
  Error(osv.NotFound)
}

pub fn check_vulns_osv_batch_failure_exits_two_test() {
  let result =
    licence_audit.run_with_clients(
      manifest_args(["check", "--allow=MIT,Apache-2.0", "--vulns"]),
      fake_fetcher,
      failing_osv_batch,
      unused_vuln_detail,
    )

  should.equal(result.exit_code, 2)
  assert string.contains(
    result.output,
    "Vulnerability check failed: OSV request failed",
  )
}

fn sbom_fetcher(name: String) -> Result(hex.PackageMetadata, hex.Error) {
  case name {
    "gleam_stdlib" -> Ok(hex.PackageMetadata(licences: ["Apache-2.0"]))
    _ -> Error(hex.NotFound)
  }
}

pub fn sbom_subcommand_prints_cyclonedx_to_stdout_test() {
  let result =
    licence_audit.run_with(
      ["sbom", "--manifest=test/fixtures/manifest_github_git.toml"],
      sbom_fetcher,
    )
  should.equal(result.exit_code, 0)
  let assert True =
    string.contains(result.output, "\"bomFormat\": \"CycloneDX\"")
  let assert True = string.contains(result.output, "\n  \"metadata\": {")
  let assert True = string.contains(result.output, "\n    \"tools\": [")
  let assert True =
    string.contains(result.output, "\"purl\": \"pkg:hex/gleam_stdlib@1.0.0\"")
  let assert True =
    string.contains(
      result.output,
      "\"purl\": \"pkg:github/tylerbutler/gluegun@fa4c8ee919138fc8ffddd2642165a89654e61999\"",
    )
  let assert True = string.contains(result.output, "\"id\": \"Apache-2.0\"")
}

pub fn sbom_subcommand_output_file_remains_compact_json_test() {
  let path = "build/tmp/sbom-output-file.json"
  let _ = simplifile.create_directory_all("build/tmp")
  let _ = simplifile.delete(path)
  let result =
    licence_audit.run_with(
      [
        "sbom",
        "--manifest=test/fixtures/manifest_github_git.toml",
        "--output=" <> path,
      ],
      sbom_fetcher,
    )
  let assert Ok(contents) = simplifile.read(from: path)

  should.equal(result.exit_code, 0)
  should.equal(result.output, "")
  let assert True = string.contains(contents, "\"bomFormat\":\"CycloneDX\"")
  let assert False = string.contains(contents, "\n  \"metadata\": {")
}

pub fn sbom_subcommand_errors_on_path_dep_test() {
  let result =
    licence_audit.run_with(
      ["sbom", "--manifest=test/fixtures/manifest_path_dep.toml"],
      sbom_fetcher,
    )
  should.equal(result.exit_code, 2)
  let assert True = string.contains(result.output, "local_dep")
  let assert True = string.contains(result.output, "path")
}

pub fn sbom_subcommand_errors_on_non_github_git_test() {
  let result =
    licence_audit.run_with(
      ["sbom", "--manifest=test/fixtures/manifest_non_github_git.toml"],
      sbom_fetcher,
    )
  should.equal(result.exit_code, 2)
  let assert True = string.contains(result.output, "gitlab.com")
}

pub fn sbom_subcommand_offline_omits_licenses_test() {
  let result =
    licence_audit.run_with(
      [
        "sbom",
        "--manifest=test/fixtures/manifest_github_git.toml",
        "--offline",
      ],
      sbom_fetcher,
    )
  should.equal(result.exit_code, 0)
  let assert False = string.contains(result.output, "\"licenses\":")
}

fn one_vuln_batch(
  purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  Ok(
    list.map(purls, fn(purl) {
      osv.BatchEntry(purl: purl, vuln_ids: ["CVE-2024-0001"])
    }),
  )
}

fn one_vuln_detail(_id: String) -> Result(osv.Vulnerability, osv.Error) {
  Ok(osv.Vulnerability(
    id: "CVE-2024-0001",
    summary: "example",
    severity: osv.High,
  ))
}

pub fn vulns_report_labels_scope_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run_with_clients(
      ["vulns", "--manifest=test/fixtures/manifest_github_git.toml"],
      fake_fetcher,
      one_vuln_batch,
      one_vuln_detail,
    )

  should.equal(exit_code, 0)
  assert string.contains(output, "gleam_stdlib")
  assert string.contains(output, "[prod]")
}
