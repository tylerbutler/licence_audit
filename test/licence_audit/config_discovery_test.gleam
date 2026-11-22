import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/cli
import licence_audit/color
import licence_audit/config
import licence_audit/error
import licence_audit/hex
import licence_audit/picker
import licence_audit/progress
import licence_audit/source_archive_test
import licence_audit/update
import simplifile

const fixture_root = "test/fixtures/config_discovery"

const missing_section = "test/fixtures/config_discovery/no_policy.toml"

fn load_options() -> config.LoadOptions {
  config.LoadOptions(
    config_path: Some(missing_section),
    project_root: fixture_root,
    allow_licences: [],
    deny_licences: [],
    vuln_severity: None,
    vuln_block_unknown: None,
    ignore_config: False,
    check: False,
  )
}

fn unused_fetcher(_name: String) -> Result(hex.PackageMetadata, hex.Error) {
  panic as "invalid configuration must stop before metadata fetch"
}

fn metadata_fetcher(_name: String) -> Result(hex.PackageMetadata, hex.Error) {
  Ok(hex.licences_only(["MIT"]))
}

fn clients() -> licence_audit.Clients {
  licence_audit.Clients(
    ..licence_audit.default_clients(),
    fetcher: unused_fetcher,
    notice_clients: source_archive_test.metadata_clients(unused_fetcher),
    osv_batch_fetcher: fn(_) {
      panic as "invalid configuration must stop before OSV fetch"
    },
  )
}

pub fn explicit_missing_section_cannot_be_hidden_by_cli_policy_test() {
  list.each([False, True], fn(check) {
    list.each([False, True], fn(with_cli_policy) {
      let options = case with_cli_policy {
        False -> config.LoadOptions(..load_options(), check:)
        True ->
          config.LoadOptions(
            ..load_options(),
            check:,
            allow_licences: ["MIT"],
            deny_licences: ["GPL-3.0-only"],
            vuln_severity: Some("critical"),
            vuln_block_unknown: Some(True),
          )
      }
      should.equal(
        config.load(options),
        Error(config.MissingPolicySection(missing_section)),
      )
    })
  })
}

pub fn missing_section_diagnostic_names_file_and_exits_two_test() {
  let diagnostic =
    error.from_config_error(config.MissingPolicySection(missing_section))
  should.equal(error.exit_code(diagnostic), 2)
  should.equal(
    error.message(diagnostic),
    "Config file " <> missing_section <> " is missing [tools.licence_audit]",
  )
}

pub fn explicit_empty_section_is_not_a_missing_section_test() {
  let assert Ok(policy) =
    config.load(
      config.LoadOptions(
        ..load_options(),
        config_path: Some(fixture_root <> "/empty_policy.toml"),
      ),
    )
  should.equal(policy.allow, [])
  should.equal(policy.deny, [])
}

pub fn ignore_config_bypasses_missing_section_and_missing_file_test() {
  list.each([missing_section, fixture_root <> "/absent.toml"], fn(path) {
    let assert Ok(policy) =
      config.load(
        config.LoadOptions(
          ..load_options(),
          config_path: Some(path),
          ignore_config: True,
          check: True,
          allow_licences: ["ISC"],
        ),
      )
    should.equal(policy.allow, ["ISC"])
    should.equal(policy.deny, [])
  })
}

pub fn explicit_missing_file_remains_a_read_error_test() {
  let path = fixture_root <> "/absent.toml"
  should.equal(
    config.load(config.LoadOptions(..load_options(), config_path: Some(path))),
    Error(config.FileReadError(path)),
  )
}

pub fn implicit_missing_section_keeps_report_and_cli_policy_behavior_test() {
  let project_root = "build/config-discovery-no-policy"
  let path = project_root <> "/gleam.toml"
  let assert Ok(_) = simplifile.create_directory_all(project_root)
  let assert Ok(_) = simplifile.write(path, "name = \"no_policy\"\n")
  let options =
    config.LoadOptions(..load_options(), config_path: None, project_root:)
  let report_result = config.load(options)
  let check_result = config.load(config.LoadOptions(..options, check: True))
  let cli_result =
    config.load(
      config.LoadOptions(..options, check: True, allow_licences: ["MIT"]),
    )
  let assert Ok(_) = simplifile.delete(path)
  let assert Ok(_) = simplifile.delete(project_root)
  let assert Ok(report_policy) = report_result
  should.equal(report_policy.allow, [])
  should.equal(check_result, Error(config.MissingPolicy))
  let assert Ok(cli_policy) = cli_result
  should.equal(cli_policy.allow, ["MIT"])
}

pub fn explicit_invalid_config_stops_report_check_and_vulns_test() {
  [["report"], ["check"], ["vulns"]]
  |> list.each(fn(command) {
    let #(result, _) =
      licence_audit.run_configured(
        command
          |> list.append([
            "--manifest=" <> fixture_root <> "/project/manifest.toml",
            "--config=" <> missing_section,
          ]),
        clients(),
        progress.disabled(),
      )
    should.equal(result.exit_code, 2)
    should.equal(
      result.output,
      "Error: Config file "
        <> missing_section
        <> " is missing [tools.licence_audit]\n",
    )
  })
}

pub fn config_and_ignore_config_are_rejected_before_reads_test() -> Nil {
  let assert Ok(original) = simplifile.read(missing_section)
  use path <- list.each([missing_section, fixture_root <> "/absent.toml"])
  use command <- list.each([[], ["report"], ["check"]])
  let #(result, _) =
    licence_audit.run_configured(
      list.append(command, [
        "--manifest=" <> fixture_root <> "/project/manifest.toml",
        "--config=" <> path,
        "--ignore-config",
      ]),
      clients(),
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  should.equal(
    result.output,
    "Error: --config and --ignore-config cannot be used together\n",
  )
  should.equal(simplifile.read(missing_section), Ok(original))
}

pub fn explicit_missing_config_stops_reports_and_checks_test() -> Nil {
  let path = fixture_root <> "/absent.toml"
  use command <- list.each([[], ["report"], ["check"]])
  let #(result, _) =
    licence_audit.run_configured(
      list.append(command, [
        "--manifest=" <> fixture_root <> "/project/manifest.toml",
        "--config=" <> path,
      ]),
      clients(),
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, path)
}

pub fn discovery_uses_manifest_sibling_not_current_directory_or_parent_test() {
  let #(result, _) =
    licence_audit.run_configured(
      ["check", "--manifest=" <> fixture_root <> "/project/manifest.toml"],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        fetcher: metadata_fetcher,
        notice_clients: source_archive_test.metadata_clients(metadata_fetcher),
      ),
      progress.disabled(),
    )
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "MIT")
}

pub fn discovery_does_not_search_above_manifest_directory_test() {
  let #(result, _) =
    licence_audit.run_configured(
      [
        "check",
        "--manifest=" <> fixture_root <> "/project/nested/manifest.toml",
      ],
      clients(),
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "requires a non-empty allow list")
}

pub fn update_creates_missing_section_in_explicit_write_target_test() {
  let path = "build/config-discovery-update.toml"
  let assert Ok(_) = simplifile.write(path, "name = \"project\"\n")
  let #(result, _) =
    update.run_with_picker(
      fixture_root <> "/project/manifest.toml",
      fixture_root,
      cli.UpdateOptions(
        manifest_path: None,
        config_path: Some(path),
        verbosity: progress.Quiet,
        color: color.Never,
        no_cache: True,
        cache_dir: None,
      ),
      source_archive_test.metadata_clients(metadata_fetcher),
      fn(_title, _labels, allow, deny) {
        should.equal(allow, [])
        should.equal(deny, [])
        Ok(picker.Selection(["MIT"], []))
      },
      progress.disabled(),
    )
  let assert Ok(contents) = simplifile.read(path)
  let assert Ok(_) = simplifile.delete(path)
  should.equal(result.exit_code, 0)
  let assert Ok(policy) = config.parse(contents)
  should.equal(policy.allow, ["MIT"])
}
