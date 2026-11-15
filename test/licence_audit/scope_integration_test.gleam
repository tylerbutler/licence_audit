import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/hex
import licence_audit/notice
import licence_audit/osv
import licence_audit/progress
import licence_audit/source_archive
import simplifile

const project_header = "name = \"scope_fixture\"\nversion = \"1.0.0\"\n"

const dev_dependencies = "[dev-dependencies]\ndev_dep = \"1.0.0\"\n"

fn archive() -> BitArray {
  let assert Ok(bytes) =
    simplifile.read_bits("test/fixtures/notices/archive_fixture/hex.tar")
  bytes
}

fn write_project(name: String, project: String, mixed: Bool) -> String {
  let root = "build/tmp/scope-185-" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(root <> "/gleam.toml", project_header <> project)
  let assert Ok(checksum) = source_archive.sha256_hex(archive())
  let packages = [
    #("dev_dep", ["dev_leaf", "shared"]),
    #("dev_leaf", []),
    #("shared", []),
  ]
  let packages = case mixed {
    False -> packages
    True -> [#("prod_dep", ["shared"]), ..packages]
  }
  let entries =
    list.map(packages, fn(package) {
      "{ name = \""
      <> package.0
      <> "\", version = \"1.0.0\", source = \"hex\", outer_checksum = \""
      <> checksum
      <> "\", requirements = ["
      <> string.join(
        list.map(package.1, fn(name) { "\"" <> name <> "\"" }),
        ",",
      )
      <> "] }"
    })
  let requirements = case mixed {
    False -> ""
    True -> "prod_dep = \"1.0.0\"\n"
  }
  let manifest_path = root <> "/manifest.toml"
  let assert Ok(_) =
    simplifile.write(
      manifest_path,
      "packages = ["
        <> string.join(entries, ",")
        <> "]\n[requirements]\ndev_dep = \"1.0.0\"\n"
        <> requirements,
    )
  manifest_path
}

fn cleanup(manifest_path: String) -> Nil {
  let assert Ok(_) =
    simplifile.delete(string.replace(manifest_path, "/manifest.toml", ""))
  Nil
}

fn no_clients() -> licence_audit.Clients {
  licence_audit.Clients(
    fetcher: fn(_) { panic as "excluded packages must not fetch metadata" },
    osv_batch_fetcher: fn(_) { panic as "excluded packages must not query OSV" },
    osv_detail_fetcher: fn(_) {
      panic as "excluded packages must not fetch advisories"
    },
    notice_clients: notice.Clients(
      fetch_hex_tarball: fn(_, _) {
        panic as "excluded packages must not fetch archives"
      },
      fetch_git_archive: fn(_, _) {
        panic as "excluded packages must not fetch Git archives"
      },
      resolve_commit: fn(_, _) {
        panic as "excluded packages must not resolve tags"
      },
      fetch_repo_archive: fn(_, _) {
        panic as "excluded packages must not fetch repositories"
      },
      fetch_spdx_index: fn(_) {
        panic as "excluded packages must not fetch SPDX indexes"
      },
      fetch_spdx: fn(_) { panic as "excluded packages must not fetch SPDX text" },
    ),
  )
}

fn selected_clients(names: List(String)) -> licence_audit.Clients {
  licence_audit.Clients(
    fetcher: fn(name) {
      assert list.contains(names, name)
      Ok(hex.licences_only(["Apache-2.0"]))
    },
    osv_batch_fetcher: fn(purls) {
      should.equal(
        purls,
        list.map(names, fn(name) { "pkg:hex/" <> name <> "@1.0.0" }),
      )
      Ok(
        list.map(purls, fn(purl) {
          osv.BatchEntry(purl: purl, vuln_ids: ["CVE-SCOPE"])
        }),
      )
    },
    osv_detail_fetcher: fn(id) {
      should.equal(id, "CVE-SCOPE")
      Ok(
        osv.Vulnerability(
          aliases: [],
          id: id,
          summary: "scope fixture advisory",
          severity: osv.High,
          scores: [],
        ),
      )
    },
    notice_clients: notice.Clients(
      ..no_clients().notice_clients,
      fetch_hex_tarball: fn(name, _) {
        assert list.contains(names, name)
        Ok(archive())
      },
    ),
  )
}

fn run(
  manifest_path: String,
  args: List(String),
  clients: licence_audit.Clients,
) -> licence_audit.RunResult {
  licence_audit.run_configured(
    list.append(args, ["--manifest=" <> manifest_path]),
    clients,
    progress.disabled(),
  ).0
}

fn component_scopes(output: String) -> List(#(String, String)) {
  let component = {
    use name <- decode.field("name", decode.string)
    use scope <- decode.field("scope", decode.string)
    decode.success(#(name, scope))
  }
  let components_decoder = {
    use components <- decode.field("components", decode.list(component))
    decode.success(components)
  }
  let assert Ok(components) = json.parse(output, components_decoder)
  components
}

pub fn dev_only_and_empty_production_tables_filter_all_commands_test() {
  use #(name, project) <- list.each([
    #("dev-only", dev_dependencies),
    #("empty-table", "[dependencies]\n" <> dev_dependencies),
  ])
  let manifest_path = write_project(name, project, False)
  list.each(
    [
      ["--ignore-config", "--prod-only"],
      ["check", "--ignore-config", "--allow=MIT", "--prod-only"],
      ["check", "--ignore-config", "--allow=MIT", "--prod-only", "--vulns"],
      ["vulns", "--ignore-config", "--prod-only"],
      ["notices", "--ignore-config"],
    ],
    fn(args) {
      let result = run(manifest_path, args, no_clients())
      should.equal(result.exit_code, 0)
      assert !string.contains(result.output, "dev_dep")
      assert !string.contains(result.output, "dev_leaf")
      assert !string.contains(result.output, "shared")
    },
  )
  let sbom = run(manifest_path, ["sbom", "--offline"], no_clients())
  should.equal(sbom.exit_code, 0)
  should.equal(component_scopes(sbom.output), [
    #("dev_dep", "optional"),
    #("dev_leaf", "optional"),
    #("shared", "optional"),
  ])
  cleanup(manifest_path)
}

pub fn dev_only_project_preserves_command_defaults_and_include_dev_test() {
  let manifest_path = write_project("defaults", dev_dependencies, False)
  let clients = selected_clients(["dev_dep", "dev_leaf", "shared"])
  let audit = run(manifest_path, ["--ignore-config"], clients)
  should.equal(audit.exit_code, 0)
  assert string.contains(audit.output, "dev_dep")
  assert string.contains(audit.output, "dev_leaf")
  let check =
    run(manifest_path, ["check", "--ignore-config", "--allow=MIT"], clients)
  should.equal(check.exit_code, 1)
  assert string.contains(check.output, "dev_dep")
  assert string.contains(check.output, "dev_leaf")
  let combined =
    run(
      manifest_path,
      ["check", "--ignore-config", "--allow=Apache-2.0", "--vulns"],
      clients,
    )
  should.equal(combined.exit_code, 1)
  assert string.contains(combined.output, "CVE-SCOPE")
  let vulns = run(manifest_path, ["vulns", "--ignore-config"], clients)
  should.equal(vulns.exit_code, 0)
  assert string.contains(vulns.output, "dev_dep 1.0.0  [dev]")
  assert string.contains(vulns.output, "dev_leaf 1.0.0  [dev]")
  assert string.contains(vulns.output, "shared 1.0.0  [dev]")
  let notices =
    run(manifest_path, ["notices", "--ignore-config", "--include-dev"], clients)
  should.equal(notices.exit_code, 0)
  assert string.contains(notices.output, "dev_dep")
  assert string.contains(notices.output, "dev_leaf")
  assert string.contains(notices.output, "shared")
  cleanup(manifest_path)
}

pub fn mixed_project_keeps_shared_transitive_production_dependencies_test() {
  let manifest_path =
    write_project(
      "mixed",
      "[dependencies]\nprod_dep = \"1.0.0\"\n" <> dev_dependencies,
      True,
    )
  let clients = selected_clients(["prod_dep", "shared"])
  list.each(
    [
      ["check", "--ignore-config", "--allow=Apache-2.0", "--prod-only"],
      ["notices", "--ignore-config"],
      ["vulns", "--ignore-config", "--prod-only"],
    ],
    fn(args) {
      let result = run(manifest_path, args, clients)
      should.equal(result.exit_code, 0)
      assert string.contains(result.output, "prod_dep")
      assert string.contains(result.output, "shared")
      assert !string.contains(result.output, "dev_dep")
      assert !string.contains(result.output, "dev_leaf")
    },
  )
  let sbom = run(manifest_path, ["sbom", "--offline"], no_clients())
  should.equal(sbom.exit_code, 0)
  should.equal(component_scopes(sbom.output), [
    #("dev_dep", "optional"),
    #("dev_leaf", "optional"),
    #("prod_dep", "required"),
    #("shared", "required"),
  ])
  cleanup(manifest_path)
}

pub fn missing_project_file_keeps_direct_dependency_fallback_test() {
  let manifest_path = write_project("missing", "", False)
  let assert Ok(_) =
    simplifile.delete_file(string.replace(
      manifest_path,
      "manifest.toml",
      "gleam.toml",
    ))
  let clients = selected_clients(["dev_dep", "dev_leaf", "shared"])
  list.each(
    [
      ["check", "--ignore-config", "--allow=Apache-2.0", "--prod-only"],
      ["vulns", "--ignore-config", "--prod-only"],
      ["notices", "--ignore-config"],
    ],
    fn(args) {
      let result = run(manifest_path, args, clients)
      should.equal(result.exit_code, 0)
      assert string.contains(result.output, "dev_dep")
      assert string.contains(result.output, "dev_leaf")
    },
  )
  let sbom = run(manifest_path, ["sbom", "--offline"], no_clients())
  should.equal(sbom.exit_code, 2)
  assert string.contains(sbom.output, "Could not read SBOM root metadata")
  cleanup(manifest_path)
}

pub fn invalid_project_configuration_fails_even_with_ignore_config_test() {
  use #(name, project) <- list.each([
    #("malformed", "name = ["),
    #("non-table", "dependencies = []\n"),
  ])
  let manifest_path = write_project(name, project, False)
  list.each(
    [
      ["check", "--ignore-config", "--allow=MIT"],
      ["check", "--ignore-config", "--allow=MIT", "--prod-only"],
      ["check", "--ignore-config", "--allow=MIT", "--prod-only", "--vulns"],
      ["vulns", "--ignore-config", "--prod-only"],
      ["vulns", "--ignore-config"],
      ["notices", "--ignore-config"],
      ["notices", "--ignore-config", "--include-dev"],
      ["sbom"],
    ],
    fn(args) {
      let result = run(manifest_path, args, no_clients())
      should.equal(result.exit_code, 2)
      let message = case args, name {
        ["sbom"], "malformed" -> "Could not parse SBOM root metadata"
        _, _ -> "Invalid production dependency configuration"
      }
      assert string.contains(result.output, message)
      assert string.contains(result.output, "/gleam.toml")
    },
  )
  cleanup(manifest_path)
}

pub fn unreadable_project_configuration_fails_in_scoped_commands_test() {
  let manifest_path = write_project("unreadable", "", False)
  let project_path =
    string.replace(manifest_path, "manifest.toml", "gleam.toml")
  let assert Ok(_) = simplifile.delete_file(project_path)
  let assert Ok(_) = simplifile.create_directory_all(project_path)
  list.each(
    [
      ["check", "--ignore-config", "--allow=MIT", "--prod-only"],
      ["vulns", "--ignore-config", "--prod-only"],
      ["notices", "--ignore-config"],
      ["sbom"],
    ],
    fn(args) {
      let result = run(manifest_path, args, no_clients())
      should.equal(result.exit_code, 2)
      let message = case args {
        ["sbom"] -> "Could not read SBOM root metadata"
        _ -> "Could not read production dependency configuration"
      }
      assert string.contains(result.output, message)
      assert string.contains(result.output, "/gleam.toml")
    },
  )
  cleanup(manifest_path)
}
