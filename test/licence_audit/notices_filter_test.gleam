import gleam/dict
import gleam/list
import gleam/option.{None}
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/config
import licence_audit/hex
import licence_audit/manifest
import licence_audit/notice
import licence_audit/progress
import licence_audit/source_archive
import simplifile

pub fn parses_notices_configuration_without_licence_policy_test() {
  should.equal(
    config.parse_notices(
      "[tools.licence_audit.notices]\ninclude = [\"one\"]\nexclude = [\"two\"]",
    ),
    Ok(config.Notices(["one"], ["two"])),
  )
  list.each(["", "[tools.licence_audit]\nallow = [\"MIT\"]"], fn(input) {
    should.equal(config.parse_notices(input), Ok(config.Notices([], [])))
  })
  let assert Ok(_) =
    config.parse(
      "[tools.licence_audit]\nallow = [\"MIT\"]\n[tools.licence_audit.notices]\ninclude = [\"one\"]",
    )
}

pub fn rejects_malformed_notices_configuration_test() {
  list.each(
    [
      "[tools.licence_audit]\nnotices = false",
      "[[tools.licence_audit.notices]]\ninclude = []",
      "[tools.licence_audit.notices]\ninclude = \"one\"",
      "[tools.licence_audit.notices]\nexclude = [1]",
      "[tools.licence_audit.notices.include]",
      "[tools.licence_audit.notices.exclude]",
      "[[tools.licence_audit.notices.include]]",
      "[[tools.licence_audit.notices.exclude]]\nname = \"one\"",
      "[tools.licence_audit.notices.include]\nname = \"one\"",
      "[tools.licence_audit.notices]\nexclude.name = \"one\"",
      "[tools.licence_audit.notices]\ninclude = { name = \"one\" }",
    ],
    fn(input) {
      let assert Error(config.InvalidField(_, _)) = config.parse_notices(input)
      Nil
    },
  )
}

fn locked_entries() -> List(manifest.SbomEntry) {
  [
    manifest.SbomEntry("hex_dep", "1.0.0", [], manifest.HexProvenance("", None)),
    manifest.SbomEntry(
      "git_dep",
      "1.0.0",
      [],
      manifest.GitProvenance("https://github.com/example/dep", "abc"),
    ),
    manifest.SbomEntry(
      "path_dep",
      "1.0.0",
      [],
      manifest.PathProvenance("local"),
    ),
    manifest.SbomEntry("dev_dep", "1.0.0", [], manifest.HexProvenance("", None)),
  ]
}

fn selected_names(
  configuration: config.Notices,
  include_dev: Bool,
) -> Result(List(String), notice.Error) {
  let locked = locked_entries()
  let selected =
    notice.selected_entries(
      manifest.SbomManifest(locked, []),
      dict.from_list([#("dev_dep", manifest.Dev)]),
      include_dev:,
    )
  case notice.filter_entries(selected, locked, configuration) {
    Ok(entries) -> Ok(list.map(entries, fn(entry) { entry.name }))
    Error(error) -> Error(error)
  }
}

pub fn filters_all_sources_with_empty_include_and_exclude_precedence_test() {
  should.equal(
    selected_names(config.Notices([], []), False),
    Ok(["hex_dep", "git_dep", "path_dep"]),
  )
  should.equal(
    selected_names(config.Notices([], ["hex_dep", "path_dep"]), False),
    Ok(["git_dep"]),
  )
  should.equal(
    selected_names(
      config.Notices(["hex_dep", "git_dep", "path_dep"], ["git_dep"]),
      False,
    ),
    Ok(["hex_dep", "path_dep"]),
  )
}

pub fn include_dev_controls_eligibility_before_filtering_test() {
  should.equal(selected_names(config.Notices(["dev_dep"], []), False), Ok([]))
  should.equal(
    selected_names(config.Notices(["dev_dep"], []), True),
    Ok(["dev_dep"]),
  )
  should.equal(
    selected_names(config.Notices(["dev_dep"], ["dev_dep"]), True),
    Ok([]),
  )
  should.equal(
    selected_names(config.Notices([], ["dev_dep"]), False),
    Ok(["hex_dep", "git_dep", "path_dep"]),
  )
}

pub fn validates_both_lists_against_all_locked_names_test() {
  should.equal(
    selected_names(
      config.Notices(["missing", "missing"], ["stale", "missing"]),
      False,
    ),
    Error(notice.UnknownPackages(["missing", "stale"])),
  )
  // Excluding a stale include must not hide the error.
  should.equal(
    selected_names(config.Notices(["missing"], ["missing"]), True),
    Error(notice.UnknownPackages(["missing"])),
  )
}

fn project(name: String, settings: String) -> String {
  let root = "build/notices-filter-test/" <> name
  let _ = simplifile.delete(root)
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(
      "[dependencies]\nhex_dep = \">= 1.0.0\"\ngit_dep = \">= 1.0.0\"\npath_dep = \">= 1.0.0\"\n[dev-dependencies]\ndev_dep = \">= 1.0.0\"\n"
        <> settings,
      to: root <> "/gleam.toml",
    )
  let assert Ok(_) =
    simplifile.write(
      "packages = [
  { name = \"hex_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"unused\" },
  { name = \"git_dep\", version = \"1.0.0\", source = \"git\", repo = \"https://github.com/example/dep\", commit = \"abc\" },
  { name = \"path_dep\", version = \"1.0.0\", source = \"path\", path = \"local\" },
  { name = \"dev_dep\", version = \"1.0.0\", source = \"path\", path = \"dev\" },
]
[requirements]
hex_dep = { version = \">= 1.0.0\" }
git_dep = { version = \">= 1.0.0\" }
path_dep = { version = \">= 1.0.0\" }
dev_dep = { version = \">= 1.0.0\" }
",
      to: root <> "/manifest.toml",
    )
  root
}

fn no_network_clients() -> licence_audit.Clients {
  licence_audit.Clients(
    ..licence_audit.default_clients(),
    fetcher: fn(_) { panic as "Unexpected Hex metadata request" },
    notice_clients: notice.Clients(
      fetch_hex_tarball: fn(_, _) { panic as "Unexpected Hex archive request" },
      fetch_git_archive: fn(_, _) { panic as "Unexpected git archive request" },
      resolve_commit: fn(_, _) { panic as "Unexpected repository request" },
      fetch_repo_archive: fn(_, _) { panic as "Unexpected repository archive" },
      fetch_spdx_index: fn(_) { panic as "Unexpected SPDX index request" },
      fetch_spdx: fn(_) { panic as "Unexpected SPDX request" },
    ),
  )
}

fn run(root: String, extra: List(String)) -> licence_audit.RunResult {
  licence_audit.run_configured(
    list.append(["notices", "--manifest=" <> root <> "/manifest.toml"], extra),
    no_network_clients(),
    progress.disabled(),
  ).0
}

pub fn notices_filters_before_metadata_and_source_reads_test() {
  let root =
    project(
      "path-only",
      "[tools.licence_audit.notices]\ninclude = [\"path_dep\"]",
    )
  let assert Ok(_) = simplifile.create_directory_all(root <> "/local")
  let assert Ok(_) =
    simplifile.write("Local licence text", to: root <> "/local/LICENSE")
  let result = run(root, [])
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "path_dep 1.0.0")
  assert string.contains(result.output, "Local licence text")
  assert !string.contains(result.output, "hex_dep 1.0.0")
  assert !string.contains(result.output, "git_dep 1.0.0")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn notices_includes_hex_and_git_but_skips_excluded_path_test() {
  let root =
    project(
      "remote",
      "[tools.licence_audit.notices]\ninclude = [\"hex_dep\", \"git_dep\", \"path_dep\"]\nexclude = [\"path_dep\"]",
    )
  let assert Ok(hex_archive) =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  let assert Ok(git_archive) =
    simplifile.read_bits(
      "test/fixtures/notices/archive_fixture/repo_with_license.tar.gz",
    )
  let assert Ok(checksum) = source_archive.sha256_hex(hex_archive)
  let assert Ok(contents) = simplifile.read(root <> "/manifest.toml")
  let assert Ok(_) =
    simplifile.write(
      string.replace(contents, "unused", checksum),
      to: root <> "/manifest.toml",
    )
  let clients = no_network_clients()
  let clients =
    licence_audit.Clients(
      ..clients,
      fetcher: fn(name) {
        should.equal(name, "hex_dep")
        Ok(hex.licences_only(["MIT"]))
      },
      notice_clients: notice.Clients(
        ..clients.notice_clients,
        fetch_hex_tarball: fn(name, _) {
          should.equal(name, "hex_dep")
          Ok(hex_archive)
        },
        fetch_git_archive: fn(_, commit) {
          should.equal(commit, "abc")
          Ok(git_archive)
        },
      ),
    )
  let result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> root <> "/manifest.toml"],
      clients,
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "hex_dep 1.0.0")
  assert string.contains(result.output, "git_dep 1.0.0")
  assert !string.contains(result.output, "path_dep 1.0.0")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn notices_exclusion_precedence_skips_missing_sources_test() {
  let root =
    project(
      "exclude-all",
      "[tools.licence_audit.notices]\ninclude = [\"hex_dep\", \"git_dep\", \"path_dep\"]\nexclude = [\"hex_dep\", \"git_dep\", \"path_dep\"]",
    )
  should.equal(run(root, []).exit_code, 0)
  let assert Ok(_) = simplifile.delete(root)
}

pub fn notices_reports_unknown_names_before_fetching_test() {
  let root =
    project(
      "unknown",
      "[tools.licence_audit.notices]\ninclude = [\"missing\"]\nexclude = [\"stale\"]",
    )
  let result = run(root, [])
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "missing, stale")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn notices_allowlist_does_not_enable_dev_dependencies_test() {
  let root =
    project("dev", "[tools.licence_audit.notices]\ninclude = [\"dev_dep\"]")
  should.equal(run(root, []).exit_code, 0)
  let assert Ok(_) = simplifile.create_directory_all(root <> "/dev")
  let assert Ok(_) =
    simplifile.write("Dev licence text", to: root <> "/dev/LICENSE")
  let result = run(root, ["--include-dev"])
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "dev_dep 1.0.0")
  assert string.contains(result.output, "Dev licence text")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn notices_dev_only_project_without_production_table_test() {
  let root = project("dev-only-no-prod-table", "")
  let assert Ok(_) =
    simplifile.write(
      "[dev-dependencies]\nhex_dep = \">= 1.0.0\"\ndev_dep = { path = \"dev\" }\n[tools.licence_audit.notices]\ninclude = [\"hex_dep\", \"dev_dep\"]",
      to: root <> "/gleam.toml",
    )
  let result = run(root, [])
  should.equal(result.exit_code, 0)
  should.equal(
    result.output,
    notice.render([], manifest_path: root <> "/manifest.toml"),
  )
  let assert Ok(settings) = simplifile.read(root <> "/gleam.toml")
  let assert Ok(_) =
    simplifile.write(
      settings <> "\nexclude = [\"stale\"]",
      to: root <> "/gleam.toml",
    )
  let unknown = run(root, [])
  should.equal(unknown.exit_code, 2)
  assert string.contains(unknown.output, "stale")
  let assert Ok(_) = simplifile.write(settings, to: root <> "/gleam.toml")

  let assert Ok(archive) =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let assert Ok(contents) = simplifile.read(root <> "/manifest.toml")
  let assert Ok(_) =
    simplifile.write(
      string.replace(contents, "unused", checksum),
      to: root <> "/manifest.toml",
    )
  let assert Ok(_) = simplifile.create_directory_all(root <> "/dev")
  let assert Ok(_) =
    simplifile.write("Dev licence text", to: root <> "/dev/LICENSE")
  let clients = no_network_clients()
  let clients =
    licence_audit.Clients(
      ..clients,
      fetcher: fn(name) {
        should.equal(name, "hex_dep")
        Ok(hex.licences_only(["MIT"]))
      },
      notice_clients: notice.Clients(
        ..clients.notice_clients,
        fetch_hex_tarball: fn(name, _) {
          should.equal(name, "hex_dep")
          Ok(archive)
        },
      ),
    )
  let result =
    licence_audit.run_configured(
      ["notices", "--manifest=" <> root <> "/manifest.toml", "--include-dev"],
      clients,
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 0)
  assert string.contains(result.output, "hex_dep 1.0.0")
  assert string.contains(result.output, "dev_dep 1.0.0")
  assert string.contains(result.output, "Dev licence text")
  let assert Ok(_) = simplifile.delete(root)
}

pub fn notices_rejects_invalid_configuration_before_fetching_test() {
  let root = project("invalid", "[tools.licence_audit.notices]\ninclude = true")
  let result = run(root, [])
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "notices.include")
  let assert Ok(_) = simplifile.delete(root)
}
