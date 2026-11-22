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
import licence_audit/manifest
import licence_audit/osv
import licence_audit/path
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
  use input <- list.each([
    fixture_root <> "/project/nested",
    fixture_root <> "/project/nested/manifest.toml",
  ])
  let #(result, _) =
    licence_audit.run_configured(
      ["check", "--manifest=" <> input],
      clients(),
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "requires a non-empty allow list")
}

pub fn directory_inputs_preserve_report_check_and_vulns_discovery_test() -> Nil {
  let directory = fixture_root <> "/project"
  let clients =
    licence_audit.Clients(
      ..licence_audit.default_clients(),
      fetcher: metadata_fetcher,
      notice_clients: source_archive_test.metadata_clients(metadata_fetcher),
      osv_batch_fetcher: fn(purls) {
        Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, []) }))
      },
      osv_detail_fetcher: fn(_) { panic as "no advisory details expected" },
    )
  use command <- list.each([
    [],
    ["report"],
    ["check"],
    ["check", "--checks=all"],
    ["check", "--checks=vulns"],
    ["vulns"],
  ])
  let #(file_result, file_events) =
    licence_audit.run_configured(
      list.append(command, ["--manifest=" <> directory <> "/manifest.toml"]),
      clients,
      progress.disabled(),
    )
  let #(directory_result, directory_events) =
    licence_audit.run_configured(
      list.append(command, ["--manifest=" <> directory]),
      clients,
      progress.disabled(),
    )
  should.equal(directory_result, file_result)
  should.equal(directory_events, file_events)
  case command {
    ["check"] | ["check", "--checks=all"] ->
      should.equal(directory_result.exit_code, 1)
    _ -> should.equal(directory_result.exit_code, 0)
  }
}

pub fn directory_inputs_preserve_sbom_metadata_and_notices_paths_test() -> Nil {
  let directory = "build/manifest-directory-project"
  let assert Ok(_) = simplifile.create_directory_all(directory)
  let assert Ok(_) =
    simplifile.write(directory <> "/manifest.toml", "packages = []")
  let assert Ok(_) =
    simplifile.write(
      directory <> "/gleam.toml",
      "name = \"directory_project\"\nversion = \"1.2.3\"\n",
    )
  list.each([["sbom", "--reproducible", "--offline"], ["notices"]], fn(command) {
    let #(file_result, _) =
      licence_audit.run_configured(
        list.append(command, ["--manifest=" <> directory <> "/manifest.toml"]),
        clients(),
        progress.disabled(),
      )
    let #(directory_result, _) =
      licence_audit.run_configured(
        list.append(command, ["--manifest=" <> directory]),
        clients(),
        progress.disabled(),
      )
    should.equal(directory_result, file_result)
    should.equal(directory_result.exit_code, 0)
  })
  let assert Ok(_) = simplifile.delete(directory <> "/manifest.toml")
  let assert Ok(_) = simplifile.delete(directory <> "/gleam.toml")
  let assert Ok(_) = simplifile.delete(directory)
  Nil
}

pub fn missing_manifest_remedies_reach_consuming_commands_test() -> Nil {
  let directory = fixture_root
  use command <- list.each([
    [],
    ["report"],
    ["check", "--checks=vulns"],
    ["vulns"],
    ["sbom"],
    ["notices"],
  ])
  use input <- list.each([directory, directory <> "/manifest.toml"])
  let flags = case command {
    ["sbom"] -> []
    _ -> ["--ignore-config"]
  }
  let #(result, _) =
    licence_audit.run_configured(
      list.append(command, ["--manifest=" <> input, ..flags]),
      clients(),
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  should.equal(
    result.output,
    "Error: manifest.toml not found in "
      <> directory
      <> "\nRun 'gleam deps download', or use --manifest=PATH.\n",
  )
}

pub fn missing_manifest_stops_update_before_picker_or_write_test() -> Nil {
  use input <- list.each([fixture_root, fixture_root <> "/manifest.toml"])
  let #(result, _) =
    update.run_with_picker(
      input,
      fixture_root,
      cli.UpdateOptions(
        manifest_path: None,
        config_path: Some(missing_section),
        verbosity: progress.Quiet,
        color: color.Never,
        no_cache: True,
        cache_dir: None,
        allow: None,
        deny: None,
        dry_run: False,
      ),
      source_archive_test.metadata_clients(unused_fetcher),
      fn(_, _, _, _) { panic as "missing manifest must stop before picker" },
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  should.equal(
    result.output,
    "Error: manifest.toml not found in "
      <> fixture_root
      <> "\nRun 'gleam deps download', or use --manifest=PATH.\n",
  )
}

pub fn directory_inputs_preserve_update_policy_discovery_and_write_target_test() -> Nil {
  let directory = "build/manifest-directory-update"
  let file = directory <> "/gleam.toml"
  let original =
    "name = \"directory_update\"\n\n[tools.licence_audit]\nallow = [\"MIT\"]\ndeny = [\"GPL-3.0-only\"]\n"
  let assert Ok(_) = simplifile.create_directory_all(directory)
  let assert Ok(_) =
    simplifile.write(directory <> "/manifest.toml", "packages = []")
  let assert Ok(_) = simplifile.write(file, original)
  let results =
    list.map([directory, directory <> "/manifest.toml"], fn(input) {
      update.run_with_picker(
        input,
        path.dirname(manifest.resolve_path(input)),
        cli.UpdateOptions(
          manifest_path: None,
          config_path: None,
          verbosity: progress.Quiet,
          color: color.Never,
          no_cache: True,
          cache_dir: None,
          allow: None,
          deny: None,
          dry_run: False,
        ),
        source_archive_test.metadata_clients(unused_fetcher),
        fn(_title, _labels, allow, deny) {
          should.equal(allow, ["MIT"])
          should.equal(deny, ["GPL-3.0-only"])
          Ok(picker.Selection(allow, deny))
        },
        progress.disabled(),
      )
    })
  let assert [#(directory_result, _), #(file_result, _)] = results
  should.equal(directory_result, file_result)
  should.equal(directory_result.exit_code, 0)
  let assert Ok(contents) = simplifile.read(file)
  let assert Ok(policy) = config.parse(contents)
  should.equal(policy.allow, ["MIT"])
  should.equal(policy.deny, ["GPL-3.0-only"])
  let assert Ok(_) = simplifile.delete(directory <> "/manifest.toml")
  let assert Ok(_) = simplifile.delete(file)
  let assert Ok(_) = simplifile.delete(directory)
  Nil
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
        allow: None,
        deny: None,
        dry_run: False,
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
