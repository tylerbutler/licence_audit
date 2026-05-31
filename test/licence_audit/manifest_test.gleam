import gleam/dict
import gleam/option
import gleeunit/should
import licence_audit/manifest
import simplifile

const manifest_fixture = "# Minimal Gleam lockfile fixture for licence audit manifest parsing.\npackages = [\n  { name = \"gleam_stdlib\", version = \"1.0.0\", build_tools = [\"gleam\"], requirements = [], otp_app = \"gleam_stdlib\", source = \"hex\", outer_checksum = \"AAAA\" },\n  { name = \"argv\", version = \"1.1.0\", build_tools = [\"gleam\"], requirements = [], otp_app = \"argv\", source = \"hex\", outer_checksum = \"BBBB\" },\n  { name = \"local_dep\", version = \"0.1.0\", build_tools = [\"gleam\"], requirements = [], source = \"path\", path = \"../local_dep\" },\n  { name = \"git_dep\", version = \"2.0.0\", build_tools = [\"gleam\"], requirements = [], source = \"git\", repo = \"https://example.invalid/git_dep\" },\n]\n\n[requirements]\ngleam_stdlib = { version = \">= 1.0.0 and < 2.0.0\" }\n"

pub fn parse_returns_only_hex_packages_and_skipped_count_test() {
  let assert Ok(parsed) = manifest.parse(manifest_fixture)

  should.equal(parsed.packages, [
    manifest.Package(
      name: "gleam_stdlib",
      version: "1.0.0",
      source: manifest.Hex,
      kind: manifest.Direct,
      requirements: [],
    ),
    manifest.Package(
      name: "argv",
      version: "1.1.0",
      source: manifest.Hex,
      kind: manifest.Transitive,
      requirements: [],
    ),
  ])
  should.equal(parsed.skipped_non_hex, 2)
  should.equal(parsed.direct_names, ["gleam_stdlib"])
}

pub fn parse_errors_when_packages_is_missing_test() {
  let assert Error(error) = manifest.parse("[requirements]\n")

  should.equal(error, manifest.MissingPackages)
}

pub fn parse_errors_on_malformed_toml_test() {
  let assert Error(error) = manifest.parse("packages = [")

  case error {
    manifest.InvalidToml(_) -> Nil
    _ -> panic as "expected InvalidToml"
  }
}

pub fn parse_errors_when_package_field_has_wrong_type_test() {
  let input =
    "packages = [{ name = 42, version = \"1.0.0\", source = \"hex\" }]\n"
  let assert Error(error) = manifest.parse(input)

  case error {
    manifest.InvalidPackageField(
      package: "<unknown>",
      field: "name",
      expected: "String",
    ) -> Nil
    _ -> panic as "expected InvalidPackageField for package name"
  }
}

pub fn load_reads_manifest_from_file_test() {
  let assert Ok(parsed) = manifest.load("test/fixtures/manifest.toml")

  should.equal(parsed.skipped_non_hex, 2)
}

const path_fixture = "packages = [
  { name = \"app_a\", version = \"1.0.0\", source = \"hex\", requirements = [\"lib_b\", \"git_dep\"] },
  { name = \"lib_b\", version = \"2.0.0\", source = \"hex\", requirements = [\"lib_c\"] },
  { name = \"lib_c\", version = \"3.0.0\", source = \"hex\", requirements = [] },
  { name = \"git_dep\", version = \"0.1.0\", source = \"git\", requirements = [\"lib_c\"] },
  { name = \"orphan\", version = \"0.0.1\", source = \"hex\", requirements = [] },
]

[requirements]
app_a = { version = \">= 1.0.0\" }
"

pub fn dep_paths_reconstructs_direct_and_transitive_chains_test() {
  let assert Ok(parsed) = manifest.parse(path_fixture)
  let paths = manifest.dep_paths(parsed)

  should.equal(dict.get(paths, "app_a"), Ok(["app_a"]))
  should.equal(dict.get(paths, "lib_b"), Ok(["app_a", "lib_b"]))
  should.equal(dict.get(paths, "lib_c"), Ok(["app_a", "lib_b", "lib_c"]))
  should.equal(dict.get(paths, "git_dep"), Ok(["app_a", "git_dep"]))
  // Orphan packages (unreachable from any direct dep) are omitted.
  should.equal(dict.get(paths, "orphan"), Error(Nil))
}

pub fn parse_tags_direct_versus_transitive_kinds_test() {
  let assert Ok(parsed) = manifest.parse(path_fixture)
  let kinds =
    parsed.packages
    |> list_to_kind_dict

  should.equal(dict.get(kinds, "app_a"), Ok(manifest.Direct))
  should.equal(dict.get(kinds, "lib_b"), Ok(manifest.Transitive))
  should.equal(dict.get(kinds, "lib_c"), Ok(manifest.Transitive))
}

fn list_to_kind_dict(
  packages: List(manifest.Package),
) -> dict.Dict(String, manifest.Kind) {
  packages
  |> list_fold_kinds(dict.new())
}

fn list_fold_kinds(
  packages: List(manifest.Package),
  acc: dict.Dict(String, manifest.Kind),
) -> dict.Dict(String, manifest.Kind) {
  case packages {
    [] -> acc
    [p, ..rest] -> list_fold_kinds(rest, dict.insert(acc, p.name, p.kind))
  }
}

pub fn sbom_entries_returns_hex_provenance_test() {
  let assert Ok(contents) =
    simplifile.read("test/fixtures/manifest_github_git.toml")
  let assert Ok(parsed) = manifest.sbom_entries(contents)

  let assert [first, _] = parsed.entries
  should.equal(first.name, "gleam_stdlib")
  should.equal(first.version, "1.0.0")
  should.equal(first.kind, manifest.Direct)
  should.equal(first.requirements, [])
  should.equal(
    first.provenance,
    manifest.HexProvenance(
      outer_checksum: "0C5506589DF4C63DF5D6FFBB834562D6865C6C2AEE0019D7B37886BD6D128141",
      inner_checksum: option.None,
    ),
  )
}

pub fn sbom_entries_captures_optional_inner_checksum_test() {
  let input =
    "packages = [
  { name = \"foo\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"AAAA\", inner_checksum = \"BBBB\" },
]

[requirements]
foo = { version = \">= 1.0.0\" }
"
  let assert Ok(parsed) = manifest.sbom_entries(input)
  let assert [entry] = parsed.entries
  should.equal(
    entry.provenance,
    manifest.HexProvenance(
      outer_checksum: "AAAA",
      inner_checksum: option.Some("BBBB"),
    ),
  )
}

pub fn sbom_entries_returns_git_provenance_test() {
  let assert Ok(contents) =
    simplifile.read("test/fixtures/manifest_github_git.toml")
  let assert Ok(parsed) = manifest.sbom_entries(contents)

  let assert [_, second] = parsed.entries
  should.equal(second.name, "gluegun")
  should.equal(second.version, "0.1.0")
  should.equal(second.kind, manifest.Direct)
  should.equal(second.requirements, ["gleam_stdlib"])
  should.equal(
    second.provenance,
    manifest.GitProvenance(
      repo: "https://github.com/tylerbutler/gluegun",
      commit: "fa4c8ee919138fc8ffddd2642165a89654e61999",
    ),
  )
}

pub fn sbom_entries_exposes_root_requirements_test() {
  let assert Ok(contents) =
    simplifile.read("test/fixtures/manifest_github_git.toml")
  let assert Ok(parsed) = manifest.sbom_entries(contents)

  should.equal(parsed.root_requirements, ["gleam_stdlib", "gluegun"])
}

const scope_fixture = "packages = [
  { name = \"app_a\", version = \"1.0.0\", source = \"hex\", requirements = [\"lib_b\"] },
  { name = \"lib_b\", version = \"2.0.0\", source = \"hex\", requirements = [\"shared\"] },
  { name = \"test_helper\", version = \"1.0.0\", source = \"hex\", requirements = [\"shared\"] },
  { name = \"shared\", version = \"3.0.0\", source = \"hex\", requirements = [] },
]

[requirements]
app_a = { version = \">= 1.0.0\" }
test_helper = { version = \">= 1.0.0\" }
"

pub fn prod_direct_names_reads_dependencies_table_test() {
  let input =
    "[dependencies]\napp_a = \">= 1.0.0\"\n\n[dev_dependencies]\ntest_helper = \">= 1.0.0\"\n"
  should.equal(manifest.prod_direct_names(input), Ok(["app_a"]))
}

pub fn prod_direct_names_missing_table_is_error_test() {
  should.equal(manifest.prod_direct_names("name = \"x\"\n"), Error(Nil))
}

pub fn prod_direct_names_malformed_is_error_test() {
  should.equal(manifest.prod_direct_names("packages = ["), Error(Nil))
}

pub fn dep_scopes_classifies_prod_wins_test() {
  let assert Ok(locked) = manifest.parse(scope_fixture)
  let scopes = manifest.dep_scopes(locked, ["app_a"])

  should.equal(dict.get(scopes, "app_a"), Ok(manifest.Prod))
  should.equal(dict.get(scopes, "lib_b"), Ok(manifest.Prod))
  should.equal(dict.get(scopes, "shared"), Ok(manifest.Prod))
  should.equal(dict.get(scopes, "test_helper"), Ok(manifest.Dev))
}

pub fn dep_scopes_all_prod_fallback_test() {
  let assert Ok(locked) = manifest.parse(scope_fixture)
  let scopes = manifest.dep_scopes(locked, locked.direct_names)

  should.equal(dict.get(scopes, "app_a"), Ok(manifest.Prod))
  should.equal(dict.get(scopes, "test_helper"), Ok(manifest.Prod))
  should.equal(dict.get(scopes, "shared"), Ok(manifest.Prod))
}

pub fn scope_label_test() {
  should.equal(manifest.scope_label(manifest.Prod), "prod")
  should.equal(manifest.scope_label(manifest.Dev), "dev")
}
