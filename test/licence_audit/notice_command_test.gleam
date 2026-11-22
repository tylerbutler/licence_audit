import gleam/option.{None, Some}
import gleeunit/should
import licence_audit
import licence_audit/cli
import licence_audit/color
import licence_audit/error
import licence_audit/network
import licence_audit/notice
import licence_audit/notice_command
import licence_audit/progress
import simplifile

fn no_network_clients() -> notice.Clients {
  notice.Clients(
    fetch_hex_tarball: fn(_, _) { panic as "Unexpected Hex archive request" },
    fetch_git_archive: fn(_, _) { panic as "Unexpected git archive request" },
    resolve_commit: fn(_, _) { panic as "Unexpected repository request" },
    fetch_repo_archive: fn(_, _) { panic as "Unexpected repository archive" },
    fetch_spdx_index: fn(_) { panic as "Unexpected SPDX index request" },
    fetch_spdx: fn(_) { panic as "Unexpected SPDX request" },
  )
}

fn project(name: String, configuration: String) -> cli.NoticesOptions {
  let root = "build/notice-command-test/" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(
      "[dependencies]\ndep = { path = \"local\" }\n" <> configuration,
      to: root <> "/gleam.toml",
    )
  let assert Ok(_) =
    simplifile.write(
      "packages = [{ name = \"dep\", version = \"1.0.0\", source = \"local\", path = \"local\" }]\n[requirements]\ndep = { path = \"local\" }",
      to: root <> "/manifest.toml",
    )
  cli.NoticesOptions(
    manifest_path: Some(root <> "/manifest.toml"),
    config_path: None,
    ignore_config: False,
    verbosity: progress.Verbose,
    color: color.Never,
    output: None,
    scope: cli.Prod,
    no_cache: True,
    cache_dir: None,
  )
}

pub fn empty_selection_skips_source_reads_and_matches_root_test() -> Nil {
  let options =
    project("empty", "[tools.licence_audit.notices]\nexclude = [\"dep\"]")
  let assert Some(manifest_path) = options.manifest_path
  let clients = no_network_clients()
  let reporter = progress.capturing(progress.Verbose, "notices")
  let #(result, events) =
    network.with_command(fn() {
      let #(result, reporter) = notice_command.run(options, clients, reporter)
      #(result, progress.events(reporter))
    })
  let #(root_result, root_events) =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        notice_clients: clients,
      ),
      reporter,
    )
  should.equal(result, Ok(notice.render([], manifest_path:)))
  should.equal(result, Ok(root_result.output))
  should.equal(root_result.exit_code, 0)
  should.equal(events, root_events)
}

pub fn local_notice_document_matches_root_bytes_and_events_test() -> Nil {
  let options = project("document", "")
  let root = "build/notice-command-test/document"
  let assert Ok(_) = simplifile.create_directory_all(root <> "/local")
  let assert Ok(_) =
    simplifile.write("Local licence text", to: root <> "/local/LICENSE")
  let assert Ok(_) =
    simplifile.write(
      "name = \"dep\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]",
      to: root <> "/local/gleam.toml",
    )
  let clients = no_network_clients()
  let reporter = progress.capturing(progress.Verbose, "notices")
  let #(result, domain_reporter) =
    network.with_command(fn() { notice_command.run(options, clients, reporter) })
  let #(root_result, root_events) =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> root <> "/manifest.toml"],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        notice_clients: clients,
      ),
      reporter,
    )
  let assert Ok(text) = result
  should.equal(root_result.exit_code, 0)
  should.equal(text, root_result.output)
  should.equal(progress.events(domain_reporter), root_events)
  let output = root <> "/NOTICES.txt"
  let #(written, _) =
    network.with_command(fn() {
      notice_command.run(
        cli.NoticesOptions(..options, output: Some(output)),
        clients,
        reporter,
      )
    })
  should.equal(written, Ok(""))
  should.equal(simplifile.read(output), Ok(text))
}

pub fn missing_materials_match_root_diagnostic_test() -> Nil {
  let options = project("missing-materials", "")
  let root = "build/notice-command-test/missing-materials"
  let assert Ok(_) = simplifile.create_directory_all(root <> "/local")
  let clients = no_network_clients()
  let reporter = progress.disabled()
  let #(result, _) =
    network.with_command(fn() { notice_command.run(options, clients, reporter) })
  let assert Error(failure) = result
  should.equal(
    failure,
    error.Notices(notice.describe_error(notice.MissingLicenceText(["dep"]))),
  )
  let root_result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> root <> "/manifest.toml"],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        notice_clients: clients,
      ),
      reporter,
    ).0
  should.equal(error.exit_code(failure), root_result.exit_code)
  should.equal("Error: " <> error.message(failure) <> "\n", root_result.output)
}

pub fn output_write_failure_matches_root_diagnostic_test() -> Nil {
  let options =
    project(
      "write-failure",
      "[tools.licence_audit.notices]\nexclude = [\"dep\"]",
    )
  let root = "build/notice-command-test/write-failure"
  let options = cli.NoticesOptions(..options, output: Some(root))
  let clients = no_network_clients()
  let reporter = progress.disabled()
  let #(result, _) =
    network.with_command(fn() { notice_command.run(options, clients, reporter) })
  let assert Error(failure) = result
  let root_result =
    licence_audit.run_configured(
      [
        "notices",
        "--manifest=" <> root <> "/manifest.toml",
        "--output=" <> root,
      ],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        notice_clients: clients,
      ),
      reporter,
    ).0
  should.equal(error.exit_code(failure), 2)
  should.equal(root_result.exit_code, 2)
  should.equal("Error: " <> error.message(failure) <> "\n", root_result.output)
}

pub fn manifest_directory_uses_project_configuration_and_matches_root_test() -> Nil {
  let options =
    project("directory", "[tools.licence_audit.notices]\nexclude = [\"dep\"]")
  let root = "build/notice-command-test/directory"
  let options = cli.NoticesOptions(..options, manifest_path: Some(root))
  let clients = no_network_clients()
  let reporter = progress.capturing(progress.Verbose, "notices")
  let #(result, domain_reporter) =
    network.with_command(fn() { notice_command.run(options, clients, reporter) })
  let #(root_result, root_events) =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> root],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        notice_clients: clients,
      ),
      reporter,
    )
  should.equal(
    result,
    Ok(notice.render([], manifest_path: root <> "/manifest.toml")),
  )
  should.equal(result, Ok(root_result.output))
  should.equal(root_result.exit_code, 0)
  should.equal(progress.events(domain_reporter), root_events)
}

pub fn missing_manifest_keeps_canonical_remedy_and_matches_root_test() -> Nil {
  let options = project("missing-manifest", "")
  let manifest_path = "build/notice-command-test/missing-manifest/custom.lock"
  let options =
    cli.NoticesOptions(..options, manifest_path: Some(manifest_path))
  let clients = no_network_clients()
  let reporter = progress.capturing(progress.Verbose, "notices")
  let #(result, domain_reporter) =
    network.with_command(fn() { notice_command.run(options, clients, reporter) })
  let assert Error(failure) = result
  should.equal(
    failure,
    error.Input(
      "custom.lock not found in build/notice-command-test/missing-manifest\nRun 'gleam deps download', or use --manifest=PATH.",
    ),
  )
  let #(root_result, root_events) =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> manifest_path],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        notice_clients: clients,
      ),
      reporter,
    )
  should.equal(error.exit_code(failure), 2)
  should.equal(root_result.exit_code, 2)
  should.equal("Error: " <> error.message(failure) <> "\n", root_result.output)
  should.equal(progress.events(domain_reporter), root_events)
}
